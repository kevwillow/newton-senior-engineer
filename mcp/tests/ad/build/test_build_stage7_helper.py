"""The stage 7 templates of the build helper (option B; PLAN-1.5 task 8).

The maintainer's decisions of 2026-11-15 (DESIGN-1.5 "Decided"): K16, DC2's machine
password is rotated after its promotion and read back; K17, the
read-back polls up to 30 minutes for 0 replication failures both ways and
dcdiag on both, and forces nothing; K19, DC1 makes three runs under one
stage 7 token, each the phase after the one its own journal records, and
no other stage has that exception.

THE FIXTURES.  ``fixtures/stage7/s7-provision.txt``, ``s7-join.txt`` and
``s7-install.txt`` are the output files of the measured ops of
MEASURED-1.5 "Stage 7 on BUILD1 and BUILD2, 2026-11-15" (m7-provision,
m7-join, m7-install), the BOM and the CRLF dropped, 10.111.0.x masked as
192.0.2.x.  Two lines of ``s7-install.txt`` are not of m7-install: the
``Test-WSMan Kerberos`` line is m7-wsman's (measured, the same session
kind), and the ``shutdown /r /t 10`` line is constructed (the restart
from inside the WinRM session is unmeasured).  The ``*-constructed``
fixtures are built from the line formats of the bodies, not measured:
``repadmin /showrepl * /csv``, the full dcdiag on both DCs (its test lines
in the measured format of stage 2's read), the member read, and the DC
read with the machine password's rotation and nltest /sc_verify (open points 41, 42, 49 and 53 of
task 8).  The tests of the op bodies run the rendered script under pwsh
with fakes of the Windows commands (open point 51).

``s7-read-measured-schema.txt`` holds the rows of the measured read-back
of MEASURED-1.5 "Stage 8 on BUILD1, 2026-11-18" (DC2's inbound Schema row
holds the failure of DC2's boot, 03:03:06) around a constructed header:
the two polls of a read-back that confirms the old failure on the second
one (the maintainer's decision of 2026-11-21 on open point 77, refined).  The read-back
of that measurement ended ``converged False`` after 61 polls, so the polls
and the summary of the fixture are the line format of the body, not the
measured ones.  The poll times of the fixture (03:08:01 and 03:08:31) and
its summary ('read-back after 40 s, 2 polls') are constructed as well, and
they are not consistent with the times of the measured rows: the rows hold
successes up to 03:35:02, 27 minutes after the first poll of the fixture.

THE TESTS DRIVE THE REAL HELPER through the driver of the stage 0 to 4
tests, with the blob's file I/O replaced as well.
"""

from __future__ import annotations

import base64
import copy
import json
import re
import subprocess
from pathlib import Path
from typing import Any

import pytest

from newton_mcp.ad.build import plan
from newton_mcp.approve import approval_token
from ops_fixture import OPS  # type: ignore[import-not-found]
from pwsh_path import PWSH  # type: ignore[import-not-found]
from test_build_stages_0_4 import BASE, DRIVER, EXP, KEY_HEX, NBF, RUN, Server

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "stage7"

#: The blob of the fakes: UTF-16LE with a BOM, as djoin saves it.
BLOB = b"\xff\xfe" + "ARAIAMzMzMz=".encode("utf-16-le")
ODJ = base64.b64encode(BLOB).decode("ascii")

CP = "pve:731:nb-stage7-20261115"
BOOT_A = "2026-11-15T19:40:00.5000000Z"
BOOT_B = "2026-11-15T19:45:52.5000000Z"
BOOT_C = "2026-11-15T19:47:52.5000000Z"

DOMAIN: dict[str, Any] = {
    "dns_name": "build.newton.test",
    "netbios": "NBUILD",
    "functional_level": "Win2025",
    "site": "Default-First-Site-Name",
    "ou_tree": ["IT/Servers"],
    "groups": ["IT Admins"],
    "owner_admin": "owner-admin",
}
DC1: dict[str, Any] = {
    "device": "build1",
    "role": "dc1",
    "hostname": "BDC1",
    "ip": "192.0.2.41",
    "prefix": 24,
    "gateway": "192.0.2.1",
    "forwarders": ["192.0.2.1"],
    "checkpoint": "proxmox",
    "vmgenid": "5781ffdf-9551-49ab-b94c-1d189c4fe1cc",
    "agent": 1,
}
DC2: dict[str, Any] = dict(DC1, device="build2", role="dc2", hostname="BDC2", ip="192.0.2.42",
                           vmgenid="6781ffdf-9551-49ab-b94c-1d189c4fe1cc")
INPUTS: dict[str, Any] = {
    "domain": DOMAIN,
    "servers": [DC1, DC2],
    "baseline": {"version": "2026.11", "options": {"administrator": "random-password"}},
    "accepted_findings": [],
    "ops": dict(OPS),
}

FAKE_ODJ_IO = r"""
function Read-NewtonOdjFile {
    param([string]$Path)
    [void]$script:DriverCalls.Add([ordered]@{ kind = 'odj-read'; path = $Path })
    return [string]$script:DriverIn.fake.blob
}

function Write-NewtonOdjFile {
    param([string]$Path, [byte[]]$Bytes)
    [void]$script:DriverCalls.Add([ordered]@{ kind = 'odj-write'; path = $Path; b64 = [Convert]::ToBase64String($Bytes) })
}

function Remove-NewtonOdjFile {
    param([string]$Path)
    [void]$script:DriverCalls.Add([ordered]@{ kind = 'odj-removed'; path = $Path })
}
"""

_ANCHOR = "$script:DriverCalls = New-Object System.Collections.ArrayList\n"
assert DRIVER.count(_ANCHOR) == 1
DRIVER7 = DRIVER.replace(_ANCHOR, _ANCHOR + FAKE_ODJ_IO)


class Server7(Server):
    """One of the two servers, with the stage 7 driver and a journal
    whose entries may name their phase."""

    def __init__(self, root: Path, device: str) -> None:
        super().__init__(root)
        (root / "device.txt").write_text(device + "\n", encoding="ascii")
        self.driver.write_text(DRIVER7, encoding="utf-8")

    def write(self, records: list[dict[str, Any]]) -> None:
        directory = self.root / "journal"
        directory.mkdir(exist_ok=True)
        start = len(self.journal())
        for offset, record in enumerate(records):
            seq = start + offset
            entry = {
                "run": RUN,
                "seq": seq,
                "stage": record["stage"],
                "state": record["state"],
                "reason": "",
                "digest": record["digest"],
                "checkpoint": record.get("checkpoint", ""),
                "boot": record.get("boot", BOOT_A),
                "time": BASE - 100 + seq,
                "checks": record.get("checks", []),
            }
            if record.get("phase"):
                entry["phase"] = record["phase"]
            (directory / f"{RUN}.{seq}.json").write_text(json.dumps(entry), encoding="utf-8")


def _plan(inputs: dict[str, Any] | None = None) -> dict[str, Any]:
    return plan.plan_build(copy.deepcopy(INPUTS if inputs is None else inputs))


def _resume(the_plan: dict[str, Any]) -> dict[str, Any]:
    inputs = copy.deepcopy(INPUTS)
    inputs["resume_from"] = plan.digest(the_plan)
    inputs["secrets_from"] = plan.digest(the_plan)
    inputs["start_stage"] = "7"
    return plan.plan_build(inputs)


def _fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="ascii")


def _ok(name: str) -> dict[str, Any]:
    return {"result": 0, "output": _fixture(name)}


def _servers(tmp_path: Path) -> tuple[Server7, Server7]:
    return Server7(tmp_path / "dc1" / "install", "build1"), Server7(tmp_path / "dc2" / "install", "build2")


def _before_7(server: Server7, the_plan: dict[str, Any], role: str) -> None:
    digest = plan.digest(the_plan)
    stages = ["0", "1", "2", "3", "4", "5", "6"] if role == "dc1" else ["0", "1"]
    records: list[dict[str, Any]] = []
    for stage in stages:
        records.append({"stage": stage, "state": "started", "digest": digest})
        records.append({"stage": stage, "state": "done", "digest": digest})
    records.append({"stage": "7", "state": "checkpointed", "digest": digest, "checkpoint": CP})
    server.write(records)


def _s7(server: Server7, the_plan: dict[str, Any], state: str, phase: str, *, boot: str = BOOT_A,
        checks: list[dict[str, Any]] | None = None) -> None:
    server.write([{"stage": "7", "state": state, "digest": plan.digest(the_plan), "checkpoint": CP,
                   "phase": phase, "boot": boot, "checks": checks or []}])


def _request(the_plan: dict[str, Any], action: str = "run", *, odj: str | None = None, stage: str = "7",
             checkpoint: str = CP, key: str = KEY_HEX) -> str:
    digest = plan.digest(the_plan)
    signed = plan.stage_digest(digest, stage, checkpoint) if checkpoint else digest
    body: dict[str, Any] = {
        "run": RUN,
        "plan": base64.b64encode(plan.canonical_bytes(the_plan)).decode("ascii"),
        "stage": stage,
        "action": action,
        "token": approval_token(key, signed, NBF, EXP),
        "nbf": NBF,
        "exp": EXP,
    }
    if odj is not None:
        body["odj"] = odj
    return json.dumps(body)


def _call(server: Server7, the_plan: dict[str, Any], action: str = "run", *, odj: str | None = None,
          ops: dict[str, dict[str, Any]] | None = None, boot: str = BOOT_A, restart: bool = True,
          results: dict[str, dict[str, Any]] | None = None, running: list[str] | None = None,
          stage: str = "7", checkpoint: str = CP, now: int = BASE, key: str = KEY_HEX) -> dict[str, Any]:
    payload = {
        "mode": "request",
        "request": _request(the_plan, action, odj=odj, stage=stage, checkpoint=checkpoint, key=key),
        "fake": {
            "ops": ops or {},
            "groups": [],
            "directory": True,
            "restart": restart,
            "results": results or {},
            "running": running or [],
            "blob": ODJ,
        },
    }
    return server.drive(payload, now=now, boot=boot)


def _last7(server: Server7) -> dict[str, Any]:
    return [e for e in server.journal() if e["stage"] == "7"][-1]


def _phases(server: Server7) -> list[tuple[str, str]]:
    return [(e["state"], e.get("phase", "")) for e in server.journal() if e["stage"] == "7"]


def _ops(result: dict[str, Any]) -> list[str]:
    return [c["op"] for c in result["calls"] if c["kind"] == "op"]


def _script(result: dict[str, Any], op: str) -> str:
    return next(c["script"] for c in result["calls"] if c["kind"] == "op" and c["op"] == op)


def _values(the_plan: dict[str, Any], role: str) -> dict[str, Any]:
    values = {
        "DnsName": "build.newton.test",
        "Netbios": "NBUILD",
        "BuildUser": "newton-build",
        "Ip": "192.0.2.41" if role == "dc1" else "192.0.2.42",
        "Dc1Host": "BDC1",
        "Dc2Host": "BDC2",
        "Dc1Ip": "192.0.2.41",
        "Dc2Fqdn": "BDC2.build.newton.test",
        "SiteName": "Default-First-Site-Name",
        "BlobFile": "C:\\NewtonBuild\\out\\s7-odj.txt" if role == "dc1" else "C:\\NewtonBuild\\s7-odj.txt",
        "Reuse": "0",
    }
    return values


def _verdict(server: Server7, op: str, output: str, role: str = "dc1", **extra: str) -> dict[str, Any]:
    values = dict(_values(_plan(), role), **extra)
    return server.drive({"mode": "verdict", "op": op, "output": output, "values": values,
                         "now": BASE, "nbf": NBF, "groups": []})["verdict"]


def _names(verdict: dict[str, Any]) -> dict[str, bool]:
    return {c["name"]: c["ok"] for c in verdict["checks"]}


@pytest.fixture
def one(tmp_path: Path) -> Server7:
    return Server7(tmp_path / "install", "build1")


# ---------------------------------------------------------------------------
# the parsers, on the measured outputs
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("op", "name", "role"),
    [
        ("s7-provision", "s7-provision.txt", "dc1"),
        ("s7-install", "s7-install.txt", "dc1"),
        ("s7-join", "s7-join.txt", "dc2"),
        ("s7-read", "s7-read-constructed.txt", "dc1"),
        # the measured rows of MEASURED-1.5 "Stage 7 on BUILD1 and BUILD2": the
        # schema failure of DC2's boot, a later success on the schema NC
        ("s7-read", "s7-read-measured-schema.txt", "dc1"),
        ("s7-member", "s7-member-constructed.txt", "dc2"),
        ("s7-dc", "s7-dc-constructed.txt", "dc2"),
    ],
)
def test_each_stage_7_op_passes_on_its_fixture(one: Server7, op: str, name: str, role: str) -> None:
    verdict = _verdict(one, op, _fixture(name), role)
    assert verdict["code"] in ("", None), verdict
    assert verdict["checks"] and all(c["ok"] for c in verdict["checks"]), verdict


def test_a_provision_over_a_computer_already_there_stops_unless_a_resume_reuses_it(one: Server7) -> None:
    there = _fixture("s7-provision.txt").replace(
        "before: no computer BDC2 (Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException)",
        "before: CN=BDC2,CN=Computers,DC=build,DC=newton,DC=test",
    )
    verdict = _verdict(one, "s7-provision", there)
    assert (verdict["code"], _names(verdict)["computer_before"]) == ("readback_failed", False)
    reused = _verdict(one, "s7-provision", there, Reuse="1")
    assert reused["code"] in ("", None), reused


def test_a_provision_whose_blob_is_not_utf16_stops(one: Server7) -> None:
    verdict = _verdict(one, "s7-provision", _fixture("s7-provision.txt").replace(
        "blob first two bytes: ff fe", "blob first two bytes: 41 52"))
    assert (verdict["code"], _names(verdict)["blob"]) == ("readback_failed", False)


def test_an_install_that_did_not_restart_dc2_stops(one: Server7) -> None:
    verdict = _verdict(one, "s7-install", _fixture("s7-install.txt").replace(
        "shutdown /r /t 10 on BDC2 exit 0", "shutdown /r /t 10 on BDC2 exit 1190"))
    assert (verdict["code"], _names(verdict)["restart"]) == ("op_failed", False)


def test_an_install_whose_computer_object_is_not_a_dc_after_stops(one: Server7) -> None:
    verdict = _verdict(one, "s7-install", _fixture("s7-install.txt").replace(
        "userAccountControl 532480 | primaryGroupID 516", "userAccountControl 4096 | primaryGroupID 515"))
    assert (verdict["code"], _names(verdict)["dc_after"]) == ("readback_failed", False)


def test_a_join_whose_blob_was_not_deleted_stops(one: Server7) -> None:
    # IND-1 of a review: the join's own line that the blob
    # is gone decides; a blob left on DC2 stops the stage op_failed.
    text = _fixture("s7-join.txt")
    assert "blob deleted: True" in text
    verdict = _verdict(one, "s7-join", text.replace("blob deleted: True", "blob deleted: False"), "dc2")
    assert (verdict["code"], _names(verdict)["blob_deleted"]) == ("op_failed", False), verdict
    missing = _verdict(one, "s7-join", text.replace("blob deleted: True\n", ""), "dc2")
    assert (missing["code"], _names(missing)["blob_deleted"]) == ("op_failed", False), missing


def test_a_join_whose_dns_is_not_dc1_stops(one: Server7) -> None:
    verdict = _verdict(one, "s7-join", _fixture("s7-join.txt").replace(
        "dns client: 192.0.2.41", "dns client: 192.0.2.1"), "dc2")
    assert (verdict["code"], _names(verdict)["dns"]) == ("op_failed", False)


@pytest.mark.parametrize(
    ("old", "new", "lines"),
    [
        # one naming context failing, DC2 from DC1, the failure newer than the read-back started (20:15:00)
        ('BDC2,"DC=DomainDnsZones,DC=build,DC=newton,DC=test",Default-First-Site-Name,BDC1,RPC,0,0,',
         'BDC2,"DC=DomainDnsZones,DC=build,DC=newton,DC=test",Default-First-Site-Name,BDC1,RPC,3,2026-11-15 20:20:00,', 11),
        # DC1 holds no inbound row from DC2 for the schema
        ('showrepl_INFO,Default-First-Site-Name,BDC1,"CN=Schema,CN=Configuration,DC=build,DC=newton,DC=test",Default-First-Site-Name,BDC2,RPC,0,0,2026-11-15 20:16:31,0\n', "", 10),
        # an error row next to all the INFO rows, the header counting it
        # (IC-W1: only the parser's error-row guard can fail this case)
        ("showrepl_COLUMNS,", "showrepl_ERROR,BDC2,8524\n  showrepl_COLUMNS,", 12),
    ],
)
def test_a_replication_that_has_not_converged_both_ways_is_readback_failed(one: Server7, old: str, new: str, lines: int) -> None:
    text = _fixture("s7-read-constructed.txt")
    assert old in text
    header = "repadmin /showrepl * /csv exit 0, 11 lines:"
    assert header in text
    text = text.replace(old, new).replace(header, f"repadmin /showrepl * /csv exit 0, {lines} lines:")
    verdict = _verdict(one, "s7-read", text)
    assert (verdict["code"], _names(verdict)["replication"]) == ("readback_failed", False), verdict


def test_a_dcdiag_failure_outside_the_accepted_pair_is_readback_failed(one: Server7) -> None:
    text = _fixture("s7-dc-constructed.txt").replace("BDC2 failed test SystemLog", "BDC2 failed test Replications")
    verdict = _verdict(one, "s7-dc", text, "dc2")
    assert (verdict["code"], _names(verdict)["dcdiag_dc2"]) == ("readback_failed", False)


def test_a_read_back_with_no_block_is_readback_failed(one: Server7) -> None:
    text = "\n".join(line for line in _fixture("s7-read-constructed.txt").splitlines() if not line.startswith("read-back after"))
    verdict = _verdict(one, "s7-read", text)
    assert verdict["code"] == "readback_failed"


def test_a_machine_password_that_did_not_advance_past_the_boot_is_readback_failed(one: Server7) -> None:
    text = _fixture("s7-dc-constructed.txt")
    same = text.replace("pwdLastSet after the reset: 134392457500000000 | 2026-11-15T19:49:10.0000000Z",
                        "pwdLastSet after the reset: 134392455248383064 | 2026-11-15T19:45:24.8383064Z")
    verdict = _verdict(one, "s7-dc", same, "dc2")
    assert (verdict["code"], _names(verdict)["machine_password"]) == ("readback_failed", False)
    # advanced, but to a time before the promotion's boot
    early = text.replace("LastBootUpTime: 2026-11-15T19:47:52.0000000Z", "LastBootUpTime: 2026-11-15T19:50:52.0000000Z")
    verdict = _verdict(one, "s7-dc", early, "dc2")
    assert (verdict["code"], _names(verdict)["machine_password"]) == ("readback_failed", False)


# F3 of a review: the secure channel of a DC is read with
# nltest /sc_verify, the tool Microsoft documents for a DC; the cmdlet
# Test-ComputerSecureChannel "only works on Domain Member computers" and
# "returns false positive errors" on a DC, so it is neither run nor read.
NLTEST_OK = [
    "nltest /sc_verify exit 0, 5 lines:",
    "  Flags: b0 HAS_IP  HAS_TIMESERV",
    "  Trusted DC Name \\\\BDC1.build.newton.test",
    "  Trusted DC Connection Status Status = 0 0x0 NERR_Success",
    "  Trust Verification Status = 0 0x0 NERR_Success",
    "  The command completed successfully",
]


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("nltest /sc_verify exit 0, 5 lines:", "nltest /sc_verify exit 1, 5 lines:"),
        ("Trusted DC Connection Status Status = 0 0x0 NERR_Success",
         "Trusted DC Connection Status Status = 1311 0x51f ERROR_NO_LOGON_SERVERS"),
        ("Trust Verification Status = 0 0x0 NERR_Success",
         "Trust Verification Status = 5 0x5 ERROR_ACCESS_DENIED"),
        # a line left out, the header counting what is left, so only the
        # line's own requirement can fail it
        ("  Trust Verification Status = 0 0x0 NERR_Success\n", ""),
        ("  The command completed successfully\n", ""),
        ("  Trusted DC Connection Status Status = 0 0x0 NERR_Success\n", ""),
        # the success lines outside the block nltest's header counts
        ("nltest /sc_verify exit 0, 5 lines:", "nltest /sc_verify exit 0, 1 lines:"),
    ],
)
def test_a_secure_channel_that_nltest_does_not_verify_is_readback_failed(one: Server7, old: str, new: str) -> None:
    text = _fixture("s7-dc-constructed.txt")
    assert old in text
    text = text.replace(old, new)
    if new == "":
        text = text.replace("nltest /sc_verify exit 0, 5 lines:", "nltest /sc_verify exit 0, 4 lines:")
    verdict = _verdict(one, "s7-dc", text, "dc2")
    assert (verdict["code"], _names(verdict)["secure_channel"]) == ("readback_failed", False), verdict


def test_the_dc_read_holds_no_test_computer_secure_channel_line(one: Server7) -> None:
    text = _fixture("s7-dc-constructed.txt")
    assert "Test-ComputerSecureChannel" not in text
    assert "\n".join(NLTEST_OK) in text
    # a cmdlet line, whatever it says, is not read: only nltest decides
    false = text.replace("nltest /sc_verify exit 0", "Test-ComputerSecureChannel: False\nnltest /sc_verify exit 0")
    verdict = _verdict(one, "s7-dc", false, "dc2")
    assert verdict["code"] in ("", None) and _names(verdict)["secure_channel"] is True, verdict


def test_a_dc2_that_is_not_a_dc_after_the_promotion_boot_is_readback_failed(one: Server7) -> None:
    text = _fixture("s7-dc-constructed.txt").replace("DomainRole 4", "DomainRole 3")
    verdict = _verdict(one, "s7-dc", text, "dc2")
    assert (verdict["code"], _names(verdict)["s7_dc"]) == ("readback_failed", False)


# ---------------------------------------------------------------------------
# DC1's three runs (K19)
# ---------------------------------------------------------------------------

def _raw_request(raw: bytes, *, odj: str | None = None) -> str:
    """A stage 7 run request over plan bytes plan.py would refuse, signed
    as the owner would sign them: the helper's own grammar must refuse."""
    import hashlib

    digest = hashlib.sha256(raw).hexdigest()
    body: dict[str, Any] = {
        "run": RUN,
        "plan": base64.b64encode(raw).decode("ascii"),
        "stage": "7",
        "action": "run",
        "token": approval_token(KEY_HEX, plan.stage_digest(digest, "7", CP), NBF, EXP),
        "nbf": NBF,
        "exp": EXP,
    }
    if odj is not None:
        body["odj"] = odj
    return json.dumps(body)


@pytest.mark.parametrize(
    ("role", "key", "value"),
    [
        # DC1's request: DC2's hostname reaches only the stage 7 values
        ("dc1", "servers.1.hostname=BDC2", "servers.1.hostname=4242"),
        ("dc1", "servers.1.hostname=BDC2", "servers.1.hostname=BDC2-"),
        ("dc1", "servers.1.hostname=BDC2", "servers.1.hostname=BDC2ABCDEFGHIJKL"),
        # DC2's request: DC1's hostname
        ("dc2", "servers.0.hostname=BDC1", "servers.0.hostname=4141"),
        ("dc2", "servers.0.hostname=BDC1", "servers.0.hostname=-BDC1"),
    ],
)
def test_a_signed_plan_with_the_other_dcs_hostname_outside_the_grammar_is_schema(
        tmp_path: Path, role: str, key: str, value: str) -> None:
    # IND-2 of a review: these names reach djoin's argv and
    # WinRM; the helper's own grammar refuses them even in signed bytes.
    dc1, dc2 = _servers(tmp_path)
    server = dc1 if role == "dc1" else dc2
    text = plan.canonical_bytes(_plan()).decode("ascii")
    assert text.count(key + "\n") == 1
    raw = text.replace(key + "\n", value + "\n").encode("ascii")
    import hashlib

    digest = hashlib.sha256(raw).hexdigest()
    stages = ["0", "1", "2", "3", "4", "5", "6"] if role == "dc1" else ["0", "1"]
    records: list[dict[str, Any]] = []
    for stage in stages:
        records += [{"stage": stage, "state": "started", "digest": digest}, {"stage": stage, "state": "done", "digest": digest}]
    records.append({"stage": "7", "state": "checkpointed", "digest": digest, "checkpoint": CP})
    server.write(records)
    before = len(server.journal())
    payload = {
        "mode": "request",
        "request": _raw_request(raw, odj=None if role == "dc1" else ODJ),
        "fake": {"ops": {"s7-provision": _ok("s7-provision.txt"), "s7-join": _ok("s7-join.txt")}, "groups": [],
                 "directory": True, "restart": True, "results": {}, "running": [], "blob": ODJ},
    }
    result = server.drive(payload, now=BASE, boot=BOOT_A)
    assert (result["answer"]["ok"], result["answer"]["code"]) == (False, "schema"), result["answer"]
    assert _ops(result) == []
    assert len(server.journal()) == before

def test_dc1_runs_provision_install_and_read_back_each_after_the_phase_its_journal_records(tmp_path: Path) -> None:
    dc1, _ = _servers(tmp_path)
    the_plan = _plan()
    _before_7(dc1, the_plan, "dc1")

    first = _call(dc1, the_plan, ops={"s7-provision": _ok("s7-provision.txt")})
    assert (first["answer"]["ok"], first["answer"]["status"]) == (True, "started"), first
    assert first["answer"]["odj"] == ODJ
    assert _ops(first) == ["s7-provision"]
    assert [c["path"] for c in first["calls"] if c["kind"] == "odj-removed"] == ["C:\\NewtonBuild\\out\\s7-odj.txt"]
    assert _phases(dc1)[-2:] == [("started", "s7_provision"), ("started", "s7_provisioned")]
    # the blob is in the answer only: never in the journal
    assert all(ODJ not in json.dumps(e) for e in dc1.journal())

    second = _call(dc1, the_plan, ops={"s7-install": _ok("s7-install.txt")})
    assert (second["answer"]["ok"], second["answer"]["status"]) == (True, "started"), second
    assert "odj" not in second["answer"]
    assert _ops(second) == ["s7-install"]
    assert _phases(dc1)[-1] == ("started", "s7_installed")

    third = _call(dc1, the_plan, ops={"s7-read": _ok("s7-read-constructed.txt")})
    assert (third["answer"]["ok"], third["answer"]["status"]) == (True, "done"), third
    assert _ops(third) == ["s7-read"]
    assert _phases(dc1)[-1] == ("done", "s7_read")


@pytest.mark.parametrize(
    ("state", "phase"),
    [("started", "s7_provision"), ("started", "s7_install"), ("started", "s7_read"),
     ("stopped", "s7_provision"), ("stopped", "s7_install"), ("rebooting", "s7_join")],
)
def test_dc1_refuses_a_run_whose_journal_is_not_at_the_end_of_a_phase(tmp_path: Path, state: str, phase: str) -> None:
    dc1, _ = _servers(tmp_path)
    the_plan = _plan()
    _before_7(dc1, the_plan, "dc1")
    _s7(dc1, the_plan, "started", "s7_provision")
    _s7(dc1, the_plan, state, phase)
    before = len(dc1.journal())
    result = _call(dc1, the_plan, ops={op: _ok("s7-provision.txt") for op in ("s7-provision", "s7-install", "s7-read")})
    assert (result["answer"]["status"], result["answer"]["code"]) == ("refused", "out_of_order"), result
    assert _ops(result) == []
    assert len(dc1.journal()) == before


def test_dc1_refuses_a_run_after_stage_7_is_done(tmp_path: Path) -> None:
    dc1, _ = _servers(tmp_path)
    the_plan = _plan()
    _before_7(dc1, the_plan, "dc1")
    _s7(dc1, the_plan, "done", "s7_read")
    result = _call(dc1, the_plan)
    assert result["answer"]["code"] == "already_done"
    assert _ops(result) == []


def test_no_other_stage_runs_twice_under_one_plan(tmp_path: Path) -> None:
    # The K19 exception is stage 7's only: stage 6 started under this plan
    # refuses a second run, whatever a phase says.
    dc1, _ = _servers(tmp_path)
    the_plan = _plan()
    digest = plan.digest(the_plan)
    records: list[dict[str, Any]] = []
    for stage in ["0", "1", "2", "3", "4", "5"]:
        records += [{"stage": stage, "state": "started", "digest": digest}, {"stage": stage, "state": "done", "digest": digest}]
    records.append({"stage": "6", "state": "checkpointed", "digest": digest, "checkpoint": CP})
    records.append({"stage": "6", "state": "started", "digest": digest, "checkpoint": CP, "phase": "s7_provisioned"})
    dc1.write(records)
    result = _call(dc1, the_plan, stage="6")
    assert (result["answer"]["status"], result["answer"]["code"]) == ("refused", "out_of_order"), result


def test_a_provision_that_stops_answers_no_blob_and_deletes_the_file(tmp_path: Path) -> None:
    dc1, _ = _servers(tmp_path)
    the_plan = _plan()
    _before_7(dc1, the_plan, "dc1")
    failed = {"result": 1, "output": _fixture("s7-provision.txt") + "FAIL: System.Exception: djoin\n"}
    result = _call(dc1, the_plan, ops={"s7-provision": failed})
    assert (result["answer"]["ok"], result["answer"]["status"]) == (False, "stopped")
    assert "odj" not in result["answer"]
    assert [c["kind"] for c in result["calls"] if c["kind"].startswith("odj")] == ["odj-removed"]
    assert _phases(dc1)[-1] == ("stopped", "s7_provision")


def test_a_provision_still_running_at_the_end_of_the_wait_stops(tmp_path: Path) -> None:
    dc1, _ = _servers(tmp_path)
    the_plan = _plan()
    _before_7(dc1, the_plan, "dc1")
    result = _call(dc1, the_plan, ops={"s7-provision": {"result": -1, "output": "", "outcome": "running"}})
    assert (result["answer"]["ok"], result["answer"]["status"], result["answer"]["code"]) == (False, "stopped", "op_failed")
    assert "odj" not in result["answer"]


def test_dc1_refuses_a_blob_in_its_request(tmp_path: Path) -> None:
    dc1, _ = _servers(tmp_path)
    the_plan = _plan()
    _before_7(dc1, the_plan, "dc1")
    result = _call(dc1, the_plan, odj=ODJ, ops={"s7-provision": _ok("s7-provision.txt")})
    assert result["answer"]["code"] == "schema"
    assert _ops(result) == []


@pytest.mark.parametrize("action", ["status", "checkpoint"])
def test_only_a_stage_7_run_carries_a_blob(tmp_path: Path, action: str) -> None:
    _, dc2 = _servers(tmp_path)
    the_plan = _plan()
    _before_7(dc2, the_plan, "dc2")
    result = _call(dc2, the_plan, action, odj=ODJ)
    assert result["answer"]["code"] == "schema", result


def test_a_blob_outside_its_grammar_is_refused(tmp_path: Path) -> None:
    _, dc2 = _servers(tmp_path)
    the_plan = _plan()
    _before_7(dc2, the_plan, "dc2")
    for bad in ["not base64!", "A" * 32772, "QUJD"[:3]]:
        result = _call(dc2, the_plan, odj=bad, ops={"s7-join": _ok("s7-join.txt")})
        assert result["answer"]["code"] == "schema", (bad[:8], result)
        assert _ops(result) == []


# ---------------------------------------------------------------------------
# a resume plan at 7 (open point 33; IC1-resume7 of the part C triage)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(("state", "phase"), [("started", "s7_provision"), ("started", "s7_provisioned"), ("stopped", "s7_provision")])
def test_a_resume_plan_provisions_again_with_reuse_over_a_provision(tmp_path: Path, state: str, phase: str) -> None:
    dc1, _ = _servers(tmp_path)
    the_plan = _plan()
    _before_7(dc1, the_plan, "dc1")
    _s7(dc1, the_plan, "started", "s7_provision")
    if (state, phase) != ("started", "s7_provision"):
        _s7(dc1, the_plan, state, phase)
    resumed = _resume(the_plan)
    digest = plan.digest(resumed)
    dc1.write([{"stage": "7", "state": "checkpointed", "digest": digest, "checkpoint": CP}])
    there = _fixture("s7-provision.txt").replace(
        "before: no computer BDC2 (Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException)",
        "before: CN=BDC2,CN=Computers,DC=build,DC=newton,DC=test",
    )
    result = _call(dc1, resumed, ops={"s7-provision": {"result": 0, "output": there}})
    assert (result["answer"]["ok"], result["answer"]["status"]) == (True, "started"), result
    assert result["answer"]["odj"] == ODJ
    assert "$Reuse = '1'" in _script(result, "s7-provision")
    assert _last7(dc1)["digest"] == digest and _last7(dc1)["phase"] == "s7_provisioned"


@pytest.mark.parametrize(("state", "phase"), [("started", "s7_installed"), ("started", "s7_install"), ("stopped", "s7_read")])
def test_a_resume_plan_does_not_run_a_stage_7_past_its_provision(tmp_path: Path, state: str, phase: str) -> None:
    dc1, _ = _servers(tmp_path)
    the_plan = _plan()
    _before_7(dc1, the_plan, "dc1")
    _s7(dc1, the_plan, state, phase)
    resumed = _resume(the_plan)
    dc1.write([{"stage": "7", "state": "checkpointed", "digest": plan.digest(resumed), "checkpoint": CP}])
    result = _call(dc1, resumed, ops={"s7-provision": _ok("s7-provision.txt")})
    assert (result["answer"]["status"], result["answer"]["code"]) == ("refused", "out_of_order"), result
    assert _ops(result) == []


def test_a_first_provision_renders_no_reuse(tmp_path: Path) -> None:
    dc1, _ = _servers(tmp_path)
    the_plan = _plan()
    _before_7(dc1, the_plan, "dc1")
    result = _call(dc1, the_plan, ops={"s7-provision": _ok("s7-provision.txt")})
    assert "$Reuse = '0'" in _script(result, "s7-provision")


# ---------------------------------------------------------------------------
# On DC2: the join, the member read, the DC read (K16)
# ---------------------------------------------------------------------------

def test_dc2_joins_with_the_blob_reboots_reads_itself_a_member_then_a_dc(tmp_path: Path) -> None:
    _, dc2 = _servers(tmp_path)
    the_plan = _plan()
    _before_7(dc2, the_plan, "dc2")

    join = _call(dc2, the_plan, odj=ODJ, ops={"s7-join": _ok("s7-join.txt")}, boot=BOOT_A)
    assert (join["answer"]["ok"], join["answer"]["status"]) == (True, "rebooting"), join
    writes = [c for c in join["calls"] if c["kind"] == "odj-write"]
    assert [(c["path"], c["b64"]) for c in writes] == [("C:\\NewtonBuild\\s7-odj.txt", ODJ)]
    assert [c["path"] for c in join["calls"] if c["kind"] == "secret"] == ["C:\\NewtonBuild\\dsrm.bin"]
    # the DSRM file stays for DC1's install, which deletes it on DC2
    assert not [c for c in join["calls"] if c["kind"] == "secret-removed"]
    assert sum(1 for c in join["calls"] if c["kind"] == "restart") == 1
    assert _phases(dc2)[-1] == ("rebooting", "s7_join")
    assert all(ODJ not in json.dumps(e) for e in dc2.journal())

    waiting = _call(dc2, the_plan, "status", boot=BOOT_A)
    assert waiting["answer"]["status"] == "rebooting"
    assert "s7_member" not in [c["name"] for c in waiting["answer"]["checks"]]
    assert _ops(waiting) == []

    member = _call(dc2, the_plan, "status", ops={"s7-member": _ok("s7-member-constructed.txt")}, boot=BOOT_B)
    assert (member["answer"]["ok"], member["answer"]["status"]) == (True, "rebooting"), member
    assert [c["name"] for c in member["answer"]["checks"]] == ["s7_member"]
    assert not [c for c in member["calls"] if c["kind"] == "restart"]
    assert _phases(dc2)[-1] == ("rebooting", "s7_member")

    # until DC1's install restarts it, the status carries the member read
    again = _call(dc2, the_plan, "status", boot=BOOT_B)
    assert again["answer"]["status"] == "rebooting"
    assert [(c["name"], c["ok"]) for c in again["answer"]["checks"]] == [("s7_member", True)]
    assert _ops(again) == []

    dc = _call(dc2, the_plan, "status", ops={"s7-dc": _ok("s7-dc-constructed.txt")}, boot=BOOT_C)
    assert (dc["answer"]["ok"], dc["answer"]["status"]) == (True, "done"), dc
    assert {"s7_dc", "machine_password", "secure_channel"} <= {c["name"] for c in dc["answer"]["checks"]}
    assert _phases(dc2)[-1] == ("done", "s7_dc")


def test_dc2s_run_without_a_blob_is_refused(tmp_path: Path) -> None:
    _, dc2 = _servers(tmp_path)
    the_plan = _plan()
    _before_7(dc2, the_plan, "dc2")
    result = _call(dc2, the_plan, ops={"s7-join": _ok("s7-join.txt")})
    assert result["answer"]["code"] == "schema"
    assert _ops(result) == []


def test_dc2s_second_join_is_refused(tmp_path: Path) -> None:
    _, dc2 = _servers(tmp_path)
    the_plan = _plan()
    _before_7(dc2, the_plan, "dc2")
    _s7(dc2, the_plan, "rebooting", "s7_join")
    result = _call(dc2, the_plan, odj=ODJ, ops={"s7-join": _ok("s7-join.txt")})
    assert (result["answer"]["status"], result["answer"]["code"]) == ("refused", "out_of_order")
    assert _ops(result) == []


#: The owner's passphrase of the two-sided DSRM test: each server's K is
#: derived from it as newton-approve derives it.
PASSPHRASE = "correct horse battery staple"


@pytest.mark.parametrize("resumed", [False, True], ids=["first-plan", "resume-plan"])
def test_the_dsrm_dc2s_helper_installs_is_the_one_the_approval_shows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], resumed: bool
) -> None:
    """Review findings 3 and 4 of task 8 part E, both sides: DC2's helper,
    holding DC2's own K (derived from the owner's passphrase), writes a DSRM
    secret at the join; newton-approve, from the same passphrase, prints
    that same secret under DC2's device.  Under a resume plan both sides
    take the salt from its signed secrets_from (open point 71)."""
    import io
    from datetime import datetime, timezone

    from newton_mcp import approve

    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    first = _plan()
    k2 = approve.derive_k(PASSPHRASE.encode("utf-8"), "build2")
    assert k2 != KEY_HEX
    _, dc2 = _servers(tmp_path)
    (dc2.root / "key.hex").write_text(k2 + "\n", encoding="ascii")
    digest = plan.digest(first)
    dc2.write([{"stage": s, "state": st, "digest": digest} for s in ["0", "1"] for st in ["started", "done"]])
    the_plan = _resume(first) if resumed else first
    dc2.write([{"stage": "7", "state": "checkpointed", "digest": plan.digest(the_plan), "checkpoint": CP}])

    join = _call(dc2, the_plan, odj=ODJ, ops={"s7-join": _ok("s7-join.txt")}, boot=BOOT_A, key=k2)
    assert (join["answer"]["ok"], join["answer"]["status"]) == (True, "rebooting"), join
    installed = [c["secret"] for c in join["calls"] if c["kind"] == "secret"]
    assert len(installed) == 1

    plan_id = "ab" * 16
    approve._atomic_write(approve.build_plan_path(plan_id), the_plan)
    monkeypatch.setattr(approve, "_getpass", lambda prompt: PASSPHRASE, raising=True)
    monkeypatch.setattr("sys.stdin", io.StringIO(f"approve {plan_id[:8]}\n"), raising=True)
    assert approve.approve_ad_build(plan_id, now=datetime(2027, 1, 1, tzinfo=timezone.utc)) == 0
    lines = capsys.readouterr().out.splitlines()
    labels = [i for i, line in enumerate(lines) if "DSRM password of build2 (dc2)" in line]
    assert len(labels) == 1, lines
    assert lines[labels[0] + 1].strip() == installed[0]
    # and it is DC2's: DC1's K gives another one
    dc1 = [i for i, line in enumerate(lines) if "DSRM password of build1 (dc1)" in line]
    assert len(dc1) == 1 and lines[dc1[0] + 1].strip() != installed[0]


def test_a_join_that_stops_deletes_the_blob_and_the_dsrm_file(tmp_path: Path) -> None:
    _, dc2 = _servers(tmp_path)
    the_plan = _plan()
    _before_7(dc2, the_plan, "dc2")
    failed = _fixture("s7-join.txt").replace("djoin /requestODJ exit 0", "djoin /requestODJ exit 87")
    result = _call(dc2, the_plan, odj=ODJ, ops={"s7-join": {"result": 0, "output": failed}})
    assert (result["answer"]["ok"], result["answer"]["status"]) == (False, "stopped")
    assert [c["path"] for c in result["calls"] if c["kind"] == "secret-removed"] == ["C:\\NewtonBuild\\dsrm.bin"]
    assert "odj-removed" in [c["kind"] for c in result["calls"]]
    assert not [c for c in result["calls"] if c["kind"] == "restart"]


def test_a_dc2_whose_machine_password_did_not_rotate_stops(tmp_path: Path) -> None:
    _, dc2 = _servers(tmp_path)
    the_plan = _plan()
    _before_7(dc2, the_plan, "dc2")
    _s7(dc2, the_plan, "rebooting", "s7_join")
    _s7(dc2, the_plan, "rebooting", "s7_member", boot=BOOT_B)
    text = _fixture("s7-dc-constructed.txt").replace("pwdLastSet after the reset: 134392457500000000",
                                                    "pwdLastSet after the reset: 134392455248383064")
    result = _call(dc2, the_plan, "status", ops={"s7-dc": {"result": 0, "output": text}}, boot=BOOT_C)
    assert (result["answer"]["ok"], result["answer"]["status"], result["answer"]["code"]) == (False, "stopped", "readback_failed")
    assert _phases(dc2)[-1] == ("stopped", "s7_dc")


def test_a_status_of_another_plan_does_not_go_on_with_dc2s_boot(tmp_path: Path) -> None:
    _, dc2 = _servers(tmp_path)
    the_plan = _plan()
    _before_7(dc2, the_plan, "dc2")
    _s7(dc2, the_plan, "rebooting", "s7_join")
    resumed = _resume(the_plan)
    dc2.write([{"stage": "7", "state": "checkpointed", "digest": plan.digest(resumed), "checkpoint": CP}])
    result = _call(dc2, resumed, "status", ops={"s7-member": _ok("s7-member-constructed.txt")}, boot=BOOT_B)
    # the plan-of-run check refuses it first (the stage the plan resumes
    # is in flight); the stage 7 guard behind it is a second line
    assert (result["answer"]["ok"], result["answer"]["code"]) == (False, "out_of_order")
    assert _ops(result) == []


# ---------------------------------------------------------------------------
# the read-back's bound and its record path (K17)
# ---------------------------------------------------------------------------

def test_the_read_back_waits_up_to_30_minutes_and_never_past_the_tokens_bound(tmp_path: Path) -> None:
    dc1, _ = _servers(tmp_path)
    the_plan = _plan()
    _before_7(dc1, the_plan, "dc1")
    _s7(dc1, the_plan, "started", "s7_installed")
    early = _call(dc1, the_plan, ops={"s7-read": _ok("s7-read-constructed.txt")}, now=BASE)
    assert "$ReadWaitSeconds = '1800'" in _script(early, "s7-read")
    assert "$ReadPollSeconds = '30'" in _script(early, "s7-read")
    script = _script(early, "s7-read")
    assert "/kcc" not in script.lower() and "/syncall" not in script.lower() and "/replicate" not in script.lower()


def test_a_late_read_back_waits_only_to_the_tokens_bound(tmp_path: Path) -> None:
    dc1, _ = _servers(tmp_path)
    the_plan = _plan()
    _before_7(dc1, the_plan, "dc1")
    _s7(dc1, the_plan, "started", "s7_installed")
    late = BASE + 1500
    result = _call(dc1, the_plan, ops={"s7-read": _ok("s7-read-constructed.txt")}, now=late)
    expected = EXP + 900 - late - 120
    assert f"$ReadWaitSeconds = '{expected}'" in _script(result, "s7-read")


def test_a_read_back_still_running_is_recorded_from_its_result_file(tmp_path: Path) -> None:
    dc1, _ = _servers(tmp_path)
    the_plan = _plan()
    _before_7(dc1, the_plan, "dc1")
    _s7(dc1, the_plan, "started", "s7_installed")
    running = _call(dc1, the_plan, ops={"s7-read": {"result": -1, "output": "", "outcome": "running"}})
    assert (running["answer"]["ok"], running["answer"]["status"]) == (True, "started"), running
    assert _phases(dc1)[-1] == ("started", "s7_read")
    still = _call(dc1, the_plan, "status", running=["s7-read"])
    assert still["answer"]["status"] == "started"
    done = _call(dc1, the_plan, "status", results={"s7-read": _ok("s7-read-constructed.txt")})
    assert (done["answer"]["ok"], done["answer"]["status"]) == (True, "done"), done
    assert _phases(dc1)[-1] == ("done", "s7_read")


@pytest.mark.parametrize("phase", ["s7_provisioned", "s7_installed"])
def test_a_status_at_the_end_of_a_phase_records_nothing(tmp_path: Path, phase: str) -> None:
    # Only s7_read is on the record path: a status after the provision or
    # the install reads no result file and writes nothing.
    dc1, _ = _servers(tmp_path)
    the_plan = _plan()
    _before_7(dc1, the_plan, "dc1")
    _s7(dc1, the_plan, "started", phase, checks=[{"name": "s7_provision", "ok": True, "detail": "x"}])
    before = len(dc1.journal())
    result = _call(dc1, the_plan, "status")
    assert result["answer"]["status"] == "started"
    assert not [c for c in result["calls"] if c["kind"] == "read-result"]
    assert len(dc1.journal()) == before


def test_the_cleanup_deletes_a_leftover_blob_on_both_servers() -> None:
    text = (Path(__file__).resolve().parents[3] / "newton_mcp" / "ad" / "build" / "helper" / "build.ps1").read_text(encoding="utf-8")
    start = text.index("function Get-NewtonCleanupScript {")
    body = text[start:text.index("\n}\n", start)]
    assert "$script:OdjFileDc1, $script:OdjFileDc2" in body


# ---------------------------------------------------------------------------
# a review: the read-back's dcdiag must have run (X3), the
# guards a mutant survived (IC-M1), the verdict's own lines (T1) and the
# DC read's reset only on a DC (IC-L1)
# ---------------------------------------------------------------------------

READ = "s7-read-constructed.txt"


def _dcdiag_block(text: str, header: str) -> tuple[int, int]:
    """The index of a dcdiag block's header line and the count it says."""
    lines = text.split("\n")
    index = next(i for i, line in enumerate(lines) if line.startswith(header + " exit "))
    return index, int(lines[index].rsplit(", ", 1)[1].split(" ")[0])


def _replace_block(text: str, header: str, new_header: str, body: list[str]) -> str:
    lines = text.split("\n")
    index, count = _dcdiag_block(text, header)
    replaced = [new_header.format(n=len(body))] + ["  " + line for line in body]
    return "\n".join(lines[:index] + replaced + lines[index + 1 + count:])


#: DC1's read-back and DC2's own read, each with the dcdiag it holds: DC2's
#: dcdiag runs on DC2 itself (open point 77, ruled 2026-11-21).
DC = "s7-dc-constructed.txt"
DCDIAGS = [("s7-read", READ, "dc1", "dcdiag_dc1"), ("s7-dc", DC, "dc2", "dcdiag_dc2")]


@pytest.mark.parametrize(("op", "fixture", "role", "name"), DCDIAGS)
def test_a_dcdiag_that_did_not_exit_0_is_readback_failed(one: Server7, op: str, fixture: str, role: str, name: str) -> None:
    text = _fixture(fixture)
    assert "dcdiag exit 0, " in text
    verdict = _verdict(one, op, text.replace("dcdiag exit 0, ", "dcdiag exit 1, ", 1), role)
    assert (verdict["code"], _names(verdict)[name]) == ("readback_failed", False), verdict


@pytest.mark.parametrize(("op", "fixture", "role", "name"), DCDIAGS)
def test_a_dcdiag_block_that_ran_no_test_is_readback_failed(one: Server7, op: str, fixture: str, role: str, name: str) -> None:
    # The proof of X3: a block holding only an error line passed.
    only_error = ["Ldap search capability attribute search failed on server BDC2, return value = 81"]
    text = _replace_block(_fixture(fixture), "dcdiag", "dcdiag exit 0, {n} lines:", only_error)
    verdict = _verdict(one, op, text, role)
    assert (verdict["code"], _names(verdict)[name]) == ("readback_failed", False), verdict


@pytest.mark.parametrize("test", ["Replications", "Advertising", "LocatorCheck", "CheckSDRefDom"])
def test_a_dcdiag_that_did_not_pass_a_must_pass_test_is_readback_failed(one: Server7, test: str) -> None:
    text = _fixture(DC)
    lines = text.split("\n")
    index, count = _dcdiag_block(text, "dcdiag")
    kept = [line for line in lines[index + 1:index + 1 + count] if not line.endswith(" passed test " + test)]
    assert len(kept) < count
    text = "\n".join(lines[:index] + [f"dcdiag exit 0, {len(kept)} lines:"] + kept + lines[index + 1 + count:])
    verdict = _verdict(one, "s7-dc", text, "dc2")
    assert (verdict["code"], _names(verdict)["dcdiag_dc2"]) == ("readback_failed", False), verdict


def test_a_dcdiag_of_the_other_dc_does_not_pass_for_this_one(one: Server7) -> None:
    # DC1's block holding DC2's server tests is not DC1's dcdiag.
    text = _fixture(READ)
    lines = text.split("\n")
    index, count = _dcdiag_block(text, "dcdiag")
    swapped = [line.replace("BDC1", "BDC2") for line in lines[index + 1:index + 1 + count]]
    text = "\n".join(lines[:index + 1] + swapped + lines[index + 1 + count:])
    verdict = _verdict(one, "s7-read", text)
    assert (verdict["code"], _names(verdict)["dcdiag_dc1"]) == ("readback_failed", False), verdict


@pytest.mark.parametrize("line", ["......................... BDC2 failed test", "......................... BDC2 failed test Topology"])
def test_a_dcdiag_test_failed_outside_the_list_or_with_no_name_is_readback_failed(one: Server7, line: str) -> None:
    # Every test of the list passed, and one more line failed: a test the
    # list does not name, or one whose name wrapped to the next line.
    text = _fixture(DC)
    body = [*_block_lines(text, "dcdiag"), "         " + line]
    text = _replace_block(text, "dcdiag", "dcdiag exit 0, {n} lines:", body)
    verdict = _verdict(one, "s7-dc", text, "dc2")
    assert (verdict["code"], _names(verdict)["dcdiag_dc2"]) == ("readback_failed", False), verdict


def test_a_read_back_that_did_not_converge_is_readback_failed(one: Server7) -> None:
    text = _fixture(READ).replace("1 polls, converged True", "1 polls, converged False")
    verdict = _verdict(one, "s7-read", text)
    assert (verdict["code"], _names(verdict)["converged"]) == ("readback_failed", False), verdict


def test_the_read_back_check_names_the_read_back_line(one: Server7) -> None:
    # The dcdiag loop overwrote $Lines, so the detail came from DC2's block.
    verdict = _verdict(one, "s7-read", _fixture(READ))
    first = verdict["checks"][0]
    assert (first["name"], first["ok"], first["detail"]) == ("s7_read", True, "read-back after 40 s, 1 polls, converged True")


@pytest.mark.parametrize("kept", [0, 3])
def test_a_short_or_missing_dc2_block_is_readback_failed(one: Server7, kept: int) -> None:
    text = _fixture(DC)
    lines = text.split("\n")
    index, count = _dcdiag_block(text, "dcdiag")
    end = index + 1 + count
    text = "\n".join(lines[:index + (1 if kept else 0)] + lines[index + 1:index + 1 + kept] + lines[end:])
    verdict = _verdict(one, "s7-dc", text, "dc2")
    assert (verdict["code"], _names(verdict)["dcdiag_dc2"]) == ("readback_failed", False), verdict


def test_a_replication_row_with_a_last_failure_status_is_readback_failed(one: Server7) -> None:
    old = 'BDC1,"CN=Configuration,DC=build,DC=newton,DC=test",Default-First-Site-Name,BDC2,RPC,0,0,2026-11-15 20:16:31,0'
    text = _fixture(READ)
    assert old in text
    verdict = _verdict(one, "s7-read", text.replace(old, old[:-1] + "1908"))
    assert (verdict["code"], _names(verdict)["replication"]) == ("readback_failed", False), verdict


def test_the_read_back_on_dc1_reads_no_generation_id_of_dc2(one: Server7, tmp_path: Path) -> None:
    # Open point 77 (b): msDS-GenerationId is not replicated, so DC1 cannot
    # read DC2's; the check is DC2's own (s7-dc).  The output of the DC1
    # read-back holds no genid line and passes, and the body reads none.
    text = _fixture(READ)
    assert "msDS-GenerationId" not in text
    verdict = _verdict(one, "s7-read", text)
    assert "generation_id_dc2" not in _names(verdict) and verdict["code"] in ("", None), verdict
    body = one.drive({"mode": "render", "values": dict(_values(_plan(), "dc1"), ReadWaitSeconds="0", ReadPollSeconds="30"),
                      "ops": ["s7-read"]})["scripts"]["s7-read"]
    assert "GenerationId" not in body and "Get-ADComputer" not in body


@pytest.mark.parametrize(
    "line",
    [
        "msDS-GenerationId on CN=BDC2,OU=Domain Controllers,DC=build,DC=newton,DC=test: absent",
        "msDS-GenerationId on CN=BDC1,OU=Domain Controllers,DC=build,DC=newton,DC=test: present, 8 bytes, 1a2b3c4d5e6f7a8b",
    ],
)
def test_dc2s_own_read_without_its_generation_id_is_readback_failed(one: Server7, line: str) -> None:
    good = "msDS-GenerationId on CN=BDC2,OU=Domain Controllers,DC=build,DC=newton,DC=test: present, 8 bytes, 1a2b3c4d5e6f7a8b"
    text = _fixture(DC)
    assert good in text
    verdict = _verdict(one, "s7-dc", text.replace(good, line), "dc2")
    assert (verdict["code"], _names(verdict)["generation_id"]) == ("readback_failed", False), verdict


def test_a_machine_password_that_did_not_change_in_the_reset_is_readback_failed(one: Server7) -> None:
    # On K16: pwdLastSet already past the boot before the reset, and the same
    # after it: the reset did not rotate it.
    text = _fixture("s7-dc-constructed.txt").replace(
        "pwdLastSet before the reset: 134392455248383064", "pwdLastSet before the reset: 134392457500000000")
    verdict = _verdict(one, "s7-dc", text, "dc2")
    assert (verdict["code"], _names(verdict)["machine_password"]) == ("readback_failed", False), verdict


@pytest.mark.parametrize(("phase", "running"), [("s7_provisioned", "s7-provision"), ("s7_installed", "s7-install"),
                                                ("s7_provisioned", "s7-read")])
def test_dc1_refuses_a_run_while_a_stage_7_password_task_still_runs(tmp_path: Path, phase: str, running: str) -> None:
    dc1, _ = _servers(tmp_path)
    the_plan = _plan()
    _before_7(dc1, the_plan, "dc1")
    _s7(dc1, the_plan, "started", phase)
    before = len(dc1.journal())
    result = _call(dc1, the_plan, ops={op: _ok("s7-install.txt") for op in ("s7-install", "s7-read")}, running=[running])
    assert (result["answer"]["status"], result["answer"]["code"]) == ("refused", "out_of_order"), result
    assert _ops(result) == []
    assert len(dc1.journal()) == before


# -- the op bodies, run under pwsh with fakes of the Windows commands --------

BODY_FAKES = r"""
$script:Fake = [System.IO.File]::ReadAllText($FakePath) | ConvertFrom-Json
function Write-FakeCall([string]$Text) { [System.IO.File]::AppendAllText($CallPath, $Text + "`n") }
Add-Type -TypeDefinition 'namespace Microsoft.ActiveDirectory.Management { public class ADIdentityNotFoundException : System.Exception { public ADIdentityNotFoundException(string m) : base(m) {} } }'
function Import-Module { }
# The op bodies sleep between their polls; the fake sleeps a little, so a
# read-back that does not converge polls again (and its output names the
# polls) instead of spinning on the wait.  A test that needs the wait of
# the op to be a real one sets ``sleep_cap_ms``: the sleep is then the one
# the op asked for, up to that cap.
function Start-Sleep {
    param([int]$Seconds, [int]$Milliseconds = 0)
    $asked = $Seconds * 1000 + $Milliseconds
    $cap = 50
    if ($null -ne $script:Fake.sleep_cap_ms) { $cap = [int]$script:Fake.sleep_cap_ms }
    if ($asked -gt $cap) { $asked = $cap }
    [System.Threading.Thread]::Sleep($asked)
}
function Get-ADDomain { [pscustomobject]@{ DistinguishedName = 'DC=build,DC=newton,DC=test' } }
function Get-ADDomainController { }
function Get-ADComputer {
    Write-FakeCall ('Get-ADComputer ' + ($args -join ' '))
    if (-not [bool]$script:Fake.computer) { throw (New-Object Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException 'no such computer') }
    [pscustomobject]@{ DistinguishedName = 'CN=BDC2,OU=Domain Controllers,DC=build,DC=newton,DC=test'
        'msDS-GenerationId' = [byte[]](1, 2, 3, 4, 5, 6, 7, 8); pwdLastSet = [int64]134392457500000000
        userAccountControl = 532480; primaryGroupID = 516; servicePrincipalName = @(); dNSHostName = 'BDC2.build.newton.test' }
}
function djoin.exe {
    Write-FakeCall ('djoin ' + ($args -join ' '))
    $at = [array]::IndexOf([string[]]$args, '/savefile')
    if ($at -ge 0) { [System.IO.File]::WriteAllBytes([string]$args[$at + 1], [byte[]](255, 254, 65, 0)) }
    $global:LASTEXITCODE = 0
    'The provisioning request completed successfully.'
}
function Get-Acl { [pscustomobject]@{ Owner = 'BUILTIN\Administrators'; AreAccessRulesProtected = $true; Access = @() } }
$script:RepadminCalls = 0
$script:DcdiagCalls = 0
function repadmin.exe {
    Write-FakeCall ('repadmin ' + ($args -join ' '))
    $rc = [int]$script:Fake.repadmin_rc
    if ($null -ne $script:Fake.repadmin_rcs) {
        $rcs = @($script:Fake.repadmin_rcs)
        $rc = [int]$rcs[[Math]::Min($script:RepadminCalls, $rcs.Count - 1)]
    }
    $rows = @($script:Fake.repadmin)
    if ($null -ne $script:Fake.repadmin_polls) {
        $polls = @($script:Fake.repadmin_polls)
        $rows = @($polls[[Math]::Min($script:RepadminCalls, $polls.Count - 1)])
    }
    $script:RepadminCalls = $script:RepadminCalls + 1
    $global:LASTEXITCODE = $rc
    $rows
}
function dcdiag.exe {
    Write-FakeCall ('dcdiag ' + ($args -join ' '))
    $one = $script:Fake.dcdiag_local
    if ($null -ne $script:Fake.dcdiag_polls) {
        # The dcdiag of the polls of the read-back: the first one does not
        # pass, so the read-back polls again.
        $polls = @($script:Fake.dcdiag_polls)
        $one = $polls[[Math]::Min($script:DcdiagCalls, $polls.Count - 1)]
    }
    $script:DcdiagCalls = $script:DcdiagCalls + 1
    $global:LASTEXITCODE = [int]$one.rc
    @($one.lines)
}
function Get-CimInstance {
    param([string]$ClassName)
    if ($ClassName -eq 'Win32_ComputerSystem') {
        return [pscustomobject]@{ Name = 'BDC2'; DomainRole = [int]$script:Fake.domain_role; PartOfDomain = $true; Domain = 'build.newton.test' }
    }
    return [pscustomobject]@{ LastBootUpTime = [datetime]::Parse('2026-11-15T19:47:52Z').ToUniversalTime() }
}
function Reset-ComputerMachinePassword { Write-FakeCall 'Reset-ComputerMachinePassword' }
function Test-ComputerSecureChannel { Write-FakeCall 'Test-ComputerSecureChannel'; $true }
function nltest.exe {
    Write-FakeCall ('nltest ' + ($args -join ' '))
    $global:LASTEXITCODE = [int]$script:Fake.nltest_rc
    @($script:Fake.nltest)
}
"""

IDENTITY_LINE = "'task identity: ' + (whoami) + ' | auth ' + [Security.Principal.WindowsIdentity]::GetCurrent().AuthenticationType"


def _block_lines(text: str, header: str) -> list[str]:
    lines = text.split("\n")
    index, count = _dcdiag_block(text, header)
    return [line[2:] for line in lines[index + 1:index + 1 + count]]


def _rows() -> list[str]:
    text = _fixture(READ)
    lines = text.split("\n")
    index = next(i for i, line in enumerate(lines) if line.startswith("repadmin /showrepl * /csv exit 0, 11 lines:"))
    return [line[2:] for line in lines[index + 1:index + 12]]


def _good_fake() -> dict[str, Any]:
    text = _fixture(READ)
    return {
        "computer": True,
        "repadmin_rc": 0,
        "repadmin": _rows(),
        "dcdiag_dc1": {"rc": 0, "lines": _block_lines(text, "dcdiag")},
        "dcdiag_dc2": {"rc": 0, "lines": _block_lines(_fixture(DC), "dcdiag")},
        "domain_role": 4,
        "nltest_rc": 0,
        "nltest": [line[2:] for line in NLTEST_OK[1:]],
    }


def _run_body(one: Server7, tmp_path: Path, op: str, fake: dict[str, Any], role: str = "dc1",
              **extra: str) -> tuple[str, list[str]]:
    """The op's rendered script, run under pwsh with the fakes: its out
    file and the commands it called."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    # The wait of the op is a hard limit: a wait of zero would leave it no
    # pass at all, so the tests that run an op body give it a wait of two
    # seconds (the fake's sleep is short).
    values = dict(_values(_plan(), role), **{"ReadWaitSeconds": "0", "ReadPollSeconds": "30",
                                             "DiagWaitSeconds": "2", "DiagPollSeconds": "60", **extra})
    script = one.drive({"mode": "render", "values": values, "ops": [op]})["scripts"][op]
    lines = script.split("\n")
    out, result, fake_path, calls = (tmp_path / f"{op}.out", tmp_path / f"{op}.rc", tmp_path / f"{op}.json", tmp_path / f"{op}.calls")
    assert lines[2].startswith("$OutFile = ") and lines[3].startswith("$ResultFile = ")
    lines[2], lines[3] = f"$OutFile = '{out}'", f"$ResultFile = '{result}'"
    assert lines.count(IDENTITY_LINE) == 1
    lines[lines.index(IDENTITY_LINE)] = "'task identity: test'"
    fake = dict(fake, dcdiag_local=fake["dcdiag_dc2" if role == "dc2" else "dcdiag_dc1"])
    fake_path.write_text(json.dumps(fake), encoding="utf-8")
    calls.write_text("", encoding="utf-8")
    prelude = f"$FakePath = '{fake_path}'\n$CallPath = '{calls}'\n" + BODY_FAKES
    path = tmp_path / f"{op}.ps1"
    path.write_text(prelude + "\n".join(lines), encoding="utf-8")
    subprocess.run([str(PWSH), "-NoProfile", "-NonInteractive", "-File", str(path)], capture_output=True, text=True,
                   timeout=300, check=False)
    return out.read_text(encoding="utf-8-sig"), calls.read_text(encoding="utf-8").splitlines()


def test_the_read_back_body_converges_and_its_output_passes_the_parser(one: Server7, tmp_path: Path) -> None:
    output, calls = _run_body(one, tmp_path, "s7-read", _good_fake())
    assert "FAIL: " not in output, output
    assert ", 1 polls, converged True" in output, output
    assert [c.strip() for c in calls if c.startswith("dcdiag")] == ["dcdiag"]
    verdict = _verdict(one, "s7-read", output)
    assert verdict["code"] in ("", None) and all(c["ok"] for c in verdict["checks"]), verdict


def test_the_read_back_body_does_not_converge_on_a_dcdiag_that_did_not_exit_0(one: Server7, tmp_path: Path) -> None:
    fake = _good_fake()
    fake["dcdiag_dc1"]["rc"] = 1
    output, _ = _run_body(one, tmp_path, "s7-read", fake)
    assert ", 1 polls, converged False" in output, output
    assert _verdict(one, "s7-read", output)["code"] == "readback_failed"


def test_the_read_back_body_does_not_converge_on_a_dcdiag_that_ran_no_test(one: Server7, tmp_path: Path) -> None:
    fake = _good_fake()
    fake["dcdiag_dc1"]["lines"] = ["Ldap search capability attribute search failed on server BDC2, return value = 81"]
    output, _ = _run_body(one, tmp_path, "s7-read", fake)
    assert ", 1 polls, converged False" in output, output


def test_the_read_back_body_does_not_converge_on_the_other_dcs_dcdiag(one: Server7, tmp_path: Path) -> None:
    fake = _good_fake()
    fake["dcdiag_dc1"]["lines"] = [line.replace("BDC1", "BDC2") for line in fake["dcdiag_dc1"]["lines"]]
    output, _ = _run_body(one, tmp_path, "s7-read", fake)
    assert ", 1 polls, converged False" in output, output


def test_the_read_back_body_does_not_converge_on_a_failed_test_outside_the_accepted_pair(one: Server7, tmp_path: Path) -> None:
    fake = _good_fake()
    fake["dcdiag_dc1"]["lines"] = [*fake["dcdiag_dc1"]["lines"], "         ......................... BDC1 failed test Topology"]
    output, _ = _run_body(one, tmp_path, "s7-read", fake)
    assert ", 1 polls, converged False" in output, output


def test_the_read_back_body_does_not_converge_on_an_error_row(one: Server7, tmp_path: Path) -> None:
    fake = _good_fake()
    fake["repadmin"] = [*fake["repadmin"], "showrepl_ERROR,-,8227c936,LDAP error 81 (Server Down) Win32 Err 58."]
    output, _ = _run_body(one, tmp_path, "s7-read", fake)
    assert ", 1 polls, converged False" in output, output
    assert _verdict(one, "s7-read", output)["code"] == "readback_failed"


def test_the_provision_body_stops_on_a_computer_already_there_unless_it_reuses_it(one: Server7, tmp_path: Path) -> None:
    blob = tmp_path / "odj.txt"
    fake = dict(_good_fake(), computer=True)
    output, calls = _run_body(one, tmp_path / "a", "s7-provision", fake, BlobFile=str(blob), Reuse="0")
    assert "FAIL: " in output and "not a resume" in output, output
    assert not [c for c in calls if c.startswith("djoin")]
    output, calls = _run_body(one, tmp_path / "b", "s7-provision", fake, BlobFile=str(blob), Reuse="1")
    assert [c for c in calls if c.startswith("djoin")] == [
        f"djoin /provision /domain build.newton.test /machine BDC2 /savefile {blob} /reuse"], (output, calls)
    output, calls = _run_body(one, tmp_path / "c", "s7-provision", dict(fake, computer=False), BlobFile=str(blob), Reuse="0")
    assert [c for c in calls if c.startswith("djoin")] == [
        f"djoin /provision /domain build.newton.test /machine BDC2 /savefile {blob}"], (output, calls)


@pytest.mark.parametrize(("role", "resets"), [(3, False), (2, False), (5, False), (4, True)])
def test_the_dc_read_rotates_the_machine_password_only_on_a_dc(one: Server7, tmp_path: Path, role: int, resets: bool) -> None:
    # IC-L1: a DC2 that booted by itself at s7_member is a member; its
    # status must not rotate a member's password.
    output, calls = _run_body(one, tmp_path, "s7-dc", dict(_good_fake(), domain_role=role), "dc2")
    assert ("Reset-ComputerMachinePassword" in calls) is resets, (output, calls)
    if not resets:
        assert "FAIL: " in output and "not a replica domain controller" in output, output
        assert _verdict(one, "s7-dc", output, "dc2")["code"] == "readback_failed"


def test_the_read_back_body_holds_the_helpers_dcdiag_lists() -> None:
    text = (Path(__file__).resolve().parents[3] / "newton_mcp" / "ad" / "build" / "helper" / "build.ps1").read_text(encoding="utf-8")
    start = text.index("$script:OpBodies['s7-read'] = @'")
    body = text[start:text.index("\n'@\n", start)]
    must = text[text.index("$script:DcdiagMustPass = @("):]
    must = must[:must.index(")")]
    names = [n.strip().strip("'") for n in must.split("(", 1)[1].replace("\n", " ").split(",")]
    assert len(names) == 18
    for name in names:
        assert f"'{name}'" in body, name


def test_the_read_back_body_polls_again_after_a_repadmin_that_did_not_exit_0(one: Server7, tmp_path: Path) -> None:
    # IND-3 of a review: good rows from a repadmin that did
    # not exit 0 are not convergence; the poll reads again.
    fake = dict(_good_fake(), repadmin_rcs=[1, 0])
    output, calls = _run_body(one, tmp_path, "s7-read", fake, ReadWaitSeconds="600")
    polls = [line for line in output.splitlines() if line.startswith("poll ")]
    assert [p.split("repadmin /showrepl * /csv exit ")[1].split(",")[0] for p in polls] == ["1", "0"], output
    assert ", 2 polls, converged True" in output, output
    assert len([c for c in calls if c.startswith("repadmin")]) == 2
    assert [c.strip() for c in calls if c.startswith("dcdiag")] == ["dcdiag"]
    assert _verdict(one, "s7-read", output)["code"] in ("", None)


def test_the_dc_read_body_verifies_the_secure_channel_with_nltest_only(one: Server7, tmp_path: Path) -> None:
    # F3 of a review: nltest /sc_verify of the plan's domain
    # after the reset; Test-ComputerSecureChannel is never called on a DC.
    output, calls = _run_body(one, tmp_path, "s7-dc", _good_fake(), "dc2")
    assert "FAIL: " not in output, output
    assert "Test-ComputerSecureChannel" not in calls and "Test-ComputerSecureChannel" not in output
    assert [c for c in calls if c.startswith("nltest")] == ["nltest /sc_verify:build.newton.test"]
    assert calls.index("Reset-ComputerMachinePassword") < calls.index("nltest /sc_verify:build.newton.test")
    assert "\n".join(NLTEST_OK) in output, output
    # the fake's pwdLastSet does not move, so only the channel is read here
    assert _names(_verdict(one, "s7-dc", output, "dc2"))["secure_channel"] is True
    bad = dict(_good_fake(), nltest_rc=1)
    output, _ = _run_body(one, tmp_path / "bad", "s7-dc", bad, "dc2")
    verdict = _verdict(one, "s7-dc", output, "dc2")
    assert (verdict["code"], _names(verdict)["secure_channel"]) == ("readback_failed", False), verdict


# ---------------------------------------------------------------------------
# open point 77 (the maintainer, 2026-11-21, refined), on the measured rows of
# MEASURED-1.5 "Stage 8 on BUILD1, 2026-11-18": a replication row with a
# failure is accepted only when all three hold: its last failure is older
# than the read-back's start less 2 minutes, the same naming context shows
# a success with 0 failures, and a LATER poll shows the row unchanged (the
# same failure count and the same failure time).  Nothing is accepted on
# the first poll alone; (b) DC2's genid and (c) DC2's dcdiag are DC2's own
# reads (s7-dc)
# ---------------------------------------------------------------------------

MEASURED = "s7-read-measured-schema.txt"
SCHEMA_DC1_FROM_DC2 = ('BDC1,"CN=Schema,CN=Configuration,DC=build,DC=newton,DC=test",'
                       'Default-First-Site-Name,BDC2,RPC,0,0,2026-11-18 03:16:13,0')
SCHEMA_FAILURE = "RPC,1,2026-11-18 03:03:06,2026-11-18 03:01:43,1908"


def test_the_measured_old_schema_failure_with_a_later_success_passes_the_read_back(one: Server7) -> None:
    text = _fixture(MEASURED)
    assert SCHEMA_FAILURE in text
    verdict = _verdict(one, "s7-read", text)
    assert verdict["code"] in ("", None) and _names(verdict)["replication"] is True, verdict


@pytest.mark.parametrize("started", ["2026-11-18 03:03:06", "2026-11-18 03:03:00", "2026-11-18 03:01:00",
                                     "2026-11-18 03:05:06", "2026-11-18 03:05:05"])
def test_a_failure_not_older_than_the_read_back_start_minus_2_minutes_still_fails_it(one: Server7, started: str) -> None:
    text = _fixture(MEASURED).replace("read-back started: 2026-11-18 03:08:01", "read-back started: " + started)
    verdict = _verdict(one, "s7-read", text)
    assert (verdict["code"], _names(verdict)["replication"]) == ("readback_failed", False), verdict


def test_a_failure_with_no_later_success_on_its_nc_still_fails_the_read_back(one: Server7) -> None:
    # The other direction of the schema NC succeeded at 03:02:00, before the
    # failure at 03:03:06; other NCs succeeding later do not count.
    text = _fixture(MEASURED)
    assert SCHEMA_DC1_FROM_DC2 in text
    old = text.replace(SCHEMA_DC1_FROM_DC2, SCHEMA_DC1_FROM_DC2.replace("03:16:13", "03:02:00"))
    verdict = _verdict(one, "s7-read", old)
    assert (verdict["code"], _names(verdict)["replication"]) == ("readback_failed", False), verdict


def test_a_failure_whose_later_success_is_itself_a_failure_still_fails(one: Server7) -> None:
    text = _fixture(MEASURED)
    failing = text.replace(SCHEMA_DC1_FROM_DC2, SCHEMA_DC1_FROM_DC2.replace("RPC,0,0,2026-11-18 03:16:13,0", "RPC,1,2026-11-18 03:05:00,2026-11-18 03:16:13,1722"))
    verdict = _verdict(one, "s7-read", failing)
    assert (verdict["code"], _names(verdict)["replication"]) == ("readback_failed", False), verdict


def test_a_failure_just_older_than_the_2_minute_window_passes(one: Server7) -> None:
    # 03:03:06 + 2 minutes = 03:05:06: a start of 03:05:07 is the first that accepts it.
    text = _fixture(MEASURED).replace("read-back started: 2026-11-18 03:08:01", "read-back started: 2026-11-18 03:05:07")
    verdict = _verdict(one, "s7-read", text)
    assert verdict["code"] in ("", None) and _names(verdict)["replication"] is True, verdict


def test_the_measured_read_back_started_more_than_2_minutes_after_the_failure() -> None:
    # The numbers behind the window: MEASURED-1.5 has the read-back's task
    # starting at 03:08:01Z and the Schema row's last failure at 03:03:06.
    from datetime import datetime
    started, failed = datetime(2026, 11, 18, 3, 8, 1), datetime(2026, 11, 18, 3, 3, 6)
    assert (started - failed).total_seconds() == 295 and (started - failed).total_seconds() > 120


@pytest.mark.parametrize("line", ["old failures confirmed: False", None])
def test_an_old_failure_no_later_poll_confirmed_still_fails_the_read_back(one: Server7, line: str | None) -> None:
    lines = [row for row in _fixture(MEASURED).split("\n")]
    index = next(i for i, row in enumerate(lines) if row.startswith("old failures confirmed: "))
    lines[index:index + 1] = [line] if line else []
    verdict = _verdict(one, "s7-read", "\n".join(lines))
    assert (verdict["code"], _names(verdict)["replication"]) == ("readback_failed", False), verdict


def test_an_old_failure_confirmed_on_the_first_poll_alone_still_fails_the_read_back(one: Server7) -> None:
    # The op cannot confirm an old failure on the poll that saw it first, so
    # a read-back that polled once does not pass, whatever it says.
    text = _fixture(MEASURED).replace("read-back after 40 s, 2 polls, converged True",
                                       "read-back after 40 s, 1 polls, converged True")
    assert "2 polls" not in text
    verdict = _verdict(one, "s7-read", text)
    assert (verdict["code"], _names(verdict)["replication"]) == ("readback_failed", False), verdict


def test_a_read_back_with_no_start_line_accepts_no_failure(one: Server7) -> None:
    text = "\n".join(line for line in _fixture(MEASURED).splitlines() if not line.startswith("read-back started: "))
    verdict = _verdict(one, "s7-read", text)
    assert (verdict["code"], _names(verdict)["replication"]) == ("readback_failed", False), verdict


def _measured_rows() -> list[str]:
    lines = _fixture(MEASURED).split("\n")
    index = next(i for i, line in enumerate(lines) if line.startswith("repadmin /showrepl * /csv exit 0, 11 lines:"))
    return [line[2:] for line in lines[index + 1:index + 12]]


def test_the_read_back_body_accepts_an_old_failure_only_after_a_later_poll_confirms_it(one: Server7, tmp_path: Path) -> None:
    # The rows of the measured fixture: DC2's inbound Schema row holds the
    # failure of DC2's boot (03:03:06) and the other direction of the same
    # naming context succeeded after it (03:16:13).  The op accepts the row
    # only on a poll after the one that saw it first.
    fake = dict(_good_fake(), repadmin=_measured_rows())
    output, _ = _run_body(one, tmp_path, "s7-read", fake, ReadWaitSeconds="600")
    assert ", 2 polls, converged True" in output, output
    assert "old failures confirmed: True" in output, output
    assert any(line.startswith("read-back started: ") for line in output.splitlines()), output
    verdict = _verdict(one, "s7-read", output)
    assert verdict["code"] in ("", None) and all(c["ok"] for c in verdict["checks"]), verdict
    # one poll alone never accepts it
    alone, _ = _run_body(one, tmp_path / "alone", "s7-read", fake)
    assert ", 1 polls, converged False" in alone and "old failures confirmed: False" in alone, alone
    assert _verdict(one, "s7-read", alone)["code"] == "readback_failed"


def test_the_read_back_body_does_not_accept_a_failure_inside_the_2_minute_window(one: Server7, tmp_path: Path) -> None:
    # The failure is a minute old, so it is inside the two minutes before
    # the read-back's start; the success of the other direction is after it,
    # so the window is the only thing that can reject the row.
    from datetime import datetime, timedelta
    now = datetime.now()
    failure = (now - timedelta(seconds=60)).strftime("%Y-%m-%d %H:%M:%S")
    success = (now - timedelta(seconds=30)).strftime("%Y-%m-%d %H:%M:%S")
    rows = [row.replace("2026-11-18 03:03:06", failure).replace("2026-11-18 03:16:13", success)
            for row in _measured_rows()]
    output, _ = _run_body(one, tmp_path, "s7-read", dict(_good_fake(), repadmin=rows), ReadWaitSeconds="2")
    assert "converged True" not in output, output
    assert len([line for line in output.splitlines() if line.startswith("poll ")]) >= 2, output
    assert _verdict(one, "s7-read", output)["code"] == "readback_failed"


def test_the_read_back_body_does_not_accept_a_failure_that_a_later_poll_changes(one: Server7, tmp_path: Path) -> None:
    # The first poll sees the failure of DC2's boot; the second shows a
    # newer failure (a higher count and a newer time), so the row is never
    # accepted.
    first = _measured_rows()
    later = [row.replace("RPC,1,2026-11-18 03:03:06,", "RPC,2,2026-11-18 03:04:00,") for row in first]
    assert later != first
    fake = dict(_good_fake(), repadmin_polls=[first, later])
    output, _ = _run_body(one, tmp_path, "s7-read", fake, ReadWaitSeconds="2")
    assert "converged True" not in output, output
    assert len([line for line in output.splitlines() if line.startswith("poll ")]) >= 2, output
    assert _verdict(one, "s7-read", output)["code"] == "readback_failed"


def test_the_read_back_body_does_not_accept_a_failure_newer_than_its_start(one: Server7, tmp_path: Path) -> None:
    rows = [row.replace("2026-11-18 03:03:06", "2999-01-01 00:00:00") for row in _measured_rows()]
    output, _ = _run_body(one, tmp_path, "s7-read", dict(_good_fake(), repadmin=rows))
    assert ", 1 polls, converged False" in output, output
    assert _verdict(one, "s7-read", output)["code"] == "readback_failed"


#: DC2's inbound Schema row, clean: 0 failures and 0 status.
CLEAN_SCHEMA = "RPC,0,0,2026-11-18 03:16:13,0"


def _clean_measured_rows() -> list[str]:
    """The measured rows with DC2's inbound Schema row clean."""
    rows = [row.replace(SCHEMA_FAILURE, CLEAN_SCHEMA) for row in _measured_rows()]
    assert rows != _measured_rows()
    return rows


def _dcdiag_polls(fake: dict[str, Any]) -> list[dict[str, Any]]:
    """The dcdiag of the polls of a read-back: the first one does not pass
    (so the read-back polls again), the next ones do."""
    lines = list(fake["dcdiag_dc1"]["lines"])
    return [{"rc": 1, "lines": lines}, {"rc": 0, "lines": lines}]


def test_the_read_back_body_does_not_accept_a_row_that_fails_again_after_it_was_clean(one: Server7, tmp_path: Path) -> None:
    # DC2's inbound Schema row fails (the failure of DC2's boot), is clean
    # on the next poll and fails again with the same count and time: a row
    # seen clean that fails again is never accepted, though its values did
    # not change (the maintainer's strict decision of 2026-11-22), so the read-back never
    # converges.
    failing = _measured_rows()
    clean = _clean_measured_rows()
    fake = dict(_good_fake(), repadmin_polls=[failing, clean, failing])
    fake["dcdiag_polls"] = _dcdiag_polls(fake)
    output, _ = _run_body(one, tmp_path, "s7-read", fake, ReadWaitSeconds="2")
    assert len([line for line in output.splitlines() if line.startswith("poll ")]) >= 3, output
    assert "converged True" not in output, output
    assert _verdict(one, "s7-read", output)["code"] == "readback_failed"


def test_the_read_back_body_accepts_a_recorded_row_that_goes_clean_and_stays_clean(one: Server7, tmp_path: Path) -> None:
    # DC2's inbound Schema row fails, is clean on the next poll and stays
    # clean: the read-back passes on the clean state of the row.
    failing = _measured_rows()
    clean = _clean_measured_rows()
    fake = dict(_good_fake(), repadmin_polls=[failing, clean, clean])
    fake["dcdiag_polls"] = _dcdiag_polls(fake)
    output, _ = _run_body(one, tmp_path, "s7-read", fake, ReadWaitSeconds="2")
    assert ", 3 polls, converged True" in output, output
    verdict = _verdict(one, "s7-read", output)
    assert verdict["code"] in ("", None) and all(c["ok"] for c in verdict["checks"]), verdict


def test_the_read_back_body_records_a_clean_row_even_when_the_poll_returns_early(one: Server7, tmp_path: Path) -> None:
    # The poll that shows DC2's inbound Schema row clean returns early for
    # another row (a failure inside the two-minute window, in a direction
    # that is judged before the Schema row), so its dcdiag never runs; the
    # clean state of the row is recorded all the same, and the row that
    # fails again after it is never accepted.
    from datetime import datetime

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    failing = _measured_rows()
    clean = _clean_measured_rows()
    early = "BDC1,RPC,0,0,2026-11-18 03:35:02,0"
    assert sum(1 for row in clean if early in row) == 1, clean
    held = [row.replace(early, "BDC1,RPC,1," + now + ",2026-11-18 03:35:02,0") for row in clean]
    assert held != clean
    fake = dict(_good_fake(), repadmin_polls=[failing, held, failing])
    output, _ = _run_body(one, tmp_path, "s7-read", fake, ReadWaitSeconds="2")
    assert len([line for line in output.splitlines() if line.startswith("poll ")]) >= 3, output
    assert "converged True" not in output, output
    assert _verdict(one, "s7-read", output)["code"] == "readback_failed"


def test_the_read_back_body_does_not_accept_a_failure_with_no_later_success(one: Server7, tmp_path: Path) -> None:
    rows = [row.replace("BDC2,RPC,0,0,2026-11-18 03:16:13,0", "BDC2,RPC,0,0,2026-11-18 03:02:00,0") if '"CN=Schema,' in row else row
            for row in _measured_rows()]
    output, _ = _run_body(one, tmp_path, "s7-read", dict(_good_fake(), repadmin=rows))
    assert ", 1 polls, converged False" in output, output


def test_the_dc_read_runs_dcdiag_on_dc2_itself(one: Server7, tmp_path: Path) -> None:
    # Open point 77 (c): dcdiag /s:BDC2 from DC1 failed 0x6ba on the remote
    # event log; DC2 runs its own, without /s:, and its block passes.
    output, calls = _run_body(one, tmp_path, "s7-dc", _good_fake(), "dc2")
    assert "FAIL: " not in output, output
    assert [c.strip() for c in calls if c.startswith("dcdiag")] == ["dcdiag"], calls
    assert calls.index("nltest /sc_verify:build.newton.test") < [c.strip() for c in calls].index("dcdiag")
    verdict = _verdict(one, "s7-dc", output, "dc2")
    assert _names(verdict)["dcdiag_dc2"] is True and _names(verdict)["generation_id"] is True, verdict
    assert not any("/s:" in c for c in calls)


def test_the_dc_read_does_not_pass_on_a_dcdiag_that_failed_a_test_outside_the_accepted_pair(one: Server7, tmp_path: Path) -> None:
    fake = _good_fake()
    fake["dcdiag_dc2"]["lines"] = [*fake["dcdiag_dc2"]["lines"], "         ......................... BDC2 failed test KccEvent"]
    output, _ = _run_body(one, tmp_path, "s7-dc", fake, "dc2")
    verdict = _verdict(one, "s7-dc", output, "dc2")
    assert (verdict["code"], _names(verdict)["dcdiag_dc2"]) == ("readback_failed", False), verdict


# ---------------------------------------------------------------------------
# open point 77 on DC2 itself (the maintainer, 2026-11-23): DC2's own dcdiag
# may fail the Replications test only under the old-row rule s7-read applies
# ---------------------------------------------------------------------------

#: The output of DC2's own read of the lab run of 2026-11-23: the Schema
#: row of DC2's inbound replication failed (the failure of DC2's first
#: boot), every other row is clean, and the read-back's start is at
#: 02:04:30 with three polls.
MEASURED_DC = "s7-dc-measured-schema.txt"

#: DC2's inbound Schema row, failing: the failure of DC2's first boot.
DC_SCHEMA_FAILURE = ('showrepl_INFO,Default-First-Site-Name,BDC2,"CN=Schema,CN=Configuration,DC=build,DC=newton,DC=test",'
                      'Default-First-Site-Name,BDC1,RPC,1,2026-11-24 01:59:32,2026-11-24 01:58:10,1908')
#: The same row, clean.
DC_SCHEMA_CLEAN = ('showrepl_INFO,Default-First-Site-Name,BDC2,"CN=Schema,CN=Configuration,DC=build,DC=newton,DC=test",'
                    'Default-First-Site-Name,BDC1,RPC,0,0,2026-11-24 02:03:50,0')
#: DC1's inbound Schema row from BDC2: clean, with a success after the
#: failure of the other direction.
DC_SCHEMA_SUCCESS = ('showrepl_INFO,Default-First-Site-Name,BDC1,"CN=Schema,CN=Configuration,DC=build,DC=newton,DC=test",'
                      'Default-First-Site-Name,BDC2,RPC,0,0,2026-11-24 02:03:50,0')
#: DC2's inbound Configuration row, failing: a second naming context.
DC_CONFIGURATION_FAILURE = ('showrepl_INFO,Default-First-Site-Name,BDC2,"CN=Configuration,DC=build,DC=newton,DC=test",'
                             'Default-First-Site-Name,BDC1,RPC,1,2026-11-24 02:03:00,2026-11-24 02:02:00,1908')
DC_CONFIGURATION_CLEAN = ('showrepl_INFO,Default-First-Site-Name,BDC2,"CN=Configuration,DC=build,DC=newton,DC=test",'
                           'Default-First-Site-Name,BDC1,RPC,0,0,2026-11-24 02:03:45,0')


def _dc_rows() -> list[str]:
    """The rows of repadmin /showrepl * /csv of the measured fixture."""
    lines = _fixture(MEASURED_DC).split("\n")
    index = next(i for i, line in enumerate(lines) if line.startswith("repadmin /showrepl * /csv exit 0, 11 lines:"))
    return [line[2:] for line in lines[index + 1:index + 12]]


def _dc_times() -> tuple[str, str, str]:
    """The times of this moment: the failure of the row, the success of the
    other direction, and the success before the failure."""
    from datetime import datetime, timedelta

    now = datetime.now()
    return (
        (now - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S"),
        (now - timedelta(minutes=1)).strftime("%Y-%m-%d %H:%M:%S"),
        (now - timedelta(minutes=6)).strftime("%Y-%m-%d %H:%M:%S"),
    )


def _dc_rows_now() -> list[str]:
    """The rows of the measured fixture with the times of this moment: the
    failure is five minutes old, the successes a minute old.  The op reads
    them with the time of its own start."""
    failure, success, before = _dc_times()
    rows = [
        row.replace("2026-11-24 01:59:32", failure)
        .replace("2026-11-24 01:58:10", before)
        .replace("2026-11-24 02:03:50", success)
        .replace("2026-11-24 02:03:45", success)
        for row in _dc_rows()
    ]
    # Every time of the rows is one of the three of this moment: the check
    # names no date, so it holds whatever the day is.
    for row in rows:
        for stamp in re.findall(r"[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}", row):
            assert stamp in (failure, success, before), (stamp, row)
    return rows


def _dc_clean_now() -> list[str]:
    """The rows of this moment with DC2's inbound Schema row clean."""
    _, success, _ = _dc_times()
    rows: list[str] = []
    for row in _dc_rows_now():
        parts = row.split(",")
        if '"CN=Schema,' in row and parts[-4] == "1":
            parts[-4], parts[-3], parts[-2], parts[-1] = "0", "0", success, "0"
            row = ",".join(parts)
        rows.append(row)
    assert rows != _dc_rows_now(), rows
    return rows


def test_the_measured_old_schema_failure_of_dc2_passes_its_own_read(one: Server7) -> None:
    """The old-row rule of s7-read, applied to DC2's own dcdiag: the
    Replications test failed on the row of DC2's first boot, the failure is
    older than the read's start less two minutes, the other direction of the
    same naming context succeeded after it, and a later poll confirmed the
    row unchanged."""
    text = _fixture(MEASURED_DC)
    assert DC_SCHEMA_FAILURE in text
    assert DC_SCHEMA_SUCCESS in text
    verdict = _verdict(one, "s7-dc", text, "dc2")
    assert verdict["code"] in ("", None), verdict
    assert all(c["ok"] for c in verdict["checks"]), verdict


@pytest.mark.parametrize(
    ("old", "new"),
    [
        # no later poll confirmed the old failure
        ("old failures confirmed: True", "old failures confirmed: False"),
        # one poll alone never confirms an old failure
        ("read-back after 900 s, 3 polls, converged True", "read-back after 300 s, 1 polls, converged True"),
        # the failure is inside the two minutes before the read's start
        ("2026-11-24 01:59:32", "2026-11-24 02:03:00"),
        # no later success on the naming context of the failure
        ("Default-First-Site-Name,BDC2,RPC,0,0,2026-11-24 02:03:50,0",
         "Default-First-Site-Name,BDC2,RPC,0,0,2026-11-24 01:50:00,0"),
        # a second naming context fails, and the rule does not accept it
        (DC_CONFIGURATION_CLEAN, DC_CONFIGURATION_FAILURE),
        # a test of the list that must pass failed
        ("BDC2 passed test KnowsOfRoleHolders", "BDC2 failed test KnowsOfRoleHolders"),
    ],
    ids=[
        "not-confirmed",
        "one-poll",
        "inside-the-window",
        "no-later-success",
        "a-second-nc-failing",
        "a-must-pass-test-failed",
    ],
)
def test_an_old_failure_of_dc2_that_the_rule_does_not_accept_is_readback_failed(
    one: Server7, old: str, new: str
) -> None:
    text = _fixture(MEASURED_DC)
    assert old in text, old
    verdict = _verdict(one, "s7-dc", text.replace(old, new), "dc2")
    assert (verdict["code"], _names(verdict)["dcdiag_dc2"]) == ("readback_failed", False), verdict


@pytest.mark.parametrize(
    "line",
    [
        "read-back started: 2026-11-24 02:04:30",
        "old failures confirmed: True",
        "repadmin /showrepl * /csv exit 0, 11 lines:",
    ],
)
def test_a_dc_read_without_one_of_the_lines_of_the_old_row_rule_is_readback_failed(one: Server7, line: str) -> None:
    """A line that is missing means the old failure is not accepted."""
    text = "\n".join(row for row in _fixture(MEASURED_DC).splitlines() if not row.startswith(line))
    verdict = _verdict(one, "s7-dc", text, "dc2")
    assert (verdict["code"], _names(verdict)["dcdiag_dc2"]) == ("readback_failed", False), verdict


def test_the_dc_read_body_accepts_an_old_failure_only_after_a_later_poll_confirms_it(
    one: Server7, tmp_path: Path
) -> None:
    """The op runs repadmin /showrepl * /csv on every poll and prints the
    last poll's rows: its own output passes the parser."""
    fake = dict(_good_fake())
    fake["repadmin"] = _dc_rows_now()
    fake["dcdiag_dc2"]["lines"] = _block_lines(_fixture(MEASURED_DC), "dcdiag")
    output, calls = _run_body(one, tmp_path, "s7-dc", fake, "dc2", DiagWaitSeconds="2")
    assert "FAIL: " not in output, output
    assert "converged True" in output, output
    assert "old failures confirmed: True" in output, output
    assert any(line.startswith("read-back started: ") for line in output.splitlines()), output
    assert len([c for c in calls if c.startswith("repadmin")]) >= 2, calls
    verdict = _verdict(one, "s7-dc", output, "dc2")
    # the fake's pwdLastSet does not move, so the machine password is the
    # only check that fails: the dcdiag of DC2 passed.
    assert _names(verdict)["dcdiag_dc2"] is True, verdict
    assert _names(verdict)["machine_password"] is False, verdict


def test_the_dc_read_body_does_not_accept_a_row_that_fails_again_after_it_was_clean(
    one: Server7, tmp_path: Path
) -> None:
    """DC2's inbound Schema row fails, is clean on the next poll and fails
    again: a row seen clean that fails again is never accepted, though its
    values did not change (the maintainer's strict decision of 2026-11-22).
    The dcdiag of the second poll fails a test of the list as well, so the
    op goes on to the third poll."""
    failing = _dc_rows_now()
    clean = _dc_clean_now()
    fake = dict(_good_fake(), repadmin_polls=[failing, clean, failing])
    lines = _block_lines(_fixture(MEASURED_DC), "dcdiag")
    other = [*lines, "         ......................... BDC2 failed test KnowsOfRoleHolders"]
    fake["dcdiag_polls"] = [{"rc": 0, "lines": lines}, {"rc": 0, "lines": other}, {"rc": 0, "lines": lines}]
    output, _ = _run_body(one, tmp_path, "s7-dc", fake, "dc2", DiagWaitSeconds="2")
    assert "converged True" not in output, output
    assert len([line for line in output.splitlines() if line.startswith("poll ")]) >= 3, output
    verdict = _verdict(one, "s7-dc", output, "dc2")
    assert _names(verdict)["dcdiag_dc2"] is False, verdict


# ---------------------------------------------------------------------------
# the old-row rule of DC2's own dcdiag, per pass (the maintainer's rule of
# 2026-11-24): a failed ``Replications`` is accepted only on a pass that
# holds at least one failing row, every failing row of that pass accepted by
# the rule and recorded with the same signature on an EARLIER pass, and no
# row ever seen clean and then failing
# ---------------------------------------------------------------------------


def _dc_dcdiag_failed_replications() -> list[str]:
    """The dcdiag of the measured read of DC2: every test of the list passed
    by DC2 but ``Replications``, which failed."""
    return _block_lines(_fixture(MEASURED_DC), "dcdiag")


def test_the_dc_read_body_does_not_accept_a_failed_replications_when_the_rows_are_clean(
    one: Server7, tmp_path: Path
) -> None:
    """Poll 1 shows DC2's inbound Schema row failing (the failure of DC2's
    boot) and poll 2 shows every row clean.  The dcdiag still fails
    ``Replications`` on poll 2, and that failure is not accepted: repadmin
    shows no old failure at all on that pass, so the dcdiag failed for
    another reason."""
    failing = _dc_rows_now()
    clean = _dc_clean_now()
    fake = dict(_good_fake(), repadmin_polls=[failing, clean])
    fake["dcdiag_polls"] = [{"rc": 0, "lines": _dc_dcdiag_failed_replications()}]
    output, calls = _run_body(one, tmp_path, "s7-dc", fake, "dc2", DiagWaitSeconds="2")
    assert len([c for c in calls if c.startswith("repadmin")]) >= 2, calls
    assert "converged True" not in output, output
    assert "old failures confirmed: False" in output, output
    verdict = _verdict(one, "s7-dc", output, "dc2")
    assert (verdict["code"], _names(verdict)["dcdiag_dc2"]) == ("readback_failed", False), verdict


def test_the_dc_read_body_does_not_accept_a_failed_replications_after_a_clean_poll(
    one: Server7, tmp_path: Path
) -> None:
    """The row fails, is clean on the next poll, fails again and is clean
    once more: the row was seen clean and then failing, so it is never
    accepted, and a pass that holds no failing row accepts no failed
    ``Replications`` at all."""
    failing = _dc_rows_now()
    clean = _dc_clean_now()
    fake = dict(_good_fake(), repadmin_polls=[failing, clean, failing, clean])
    fake["dcdiag_polls"] = [{"rc": 0, "lines": _dc_dcdiag_failed_replications()}]
    output, calls = _run_body(one, tmp_path, "s7-dc", fake, "dc2", DiagWaitSeconds="2")
    assert len([c for c in calls if c.startswith("repadmin")]) >= 4, calls
    assert "converged True" not in output, output
    assert "old failures confirmed: False" in output, output
    verdict = _verdict(one, "s7-dc", output, "dc2")
    assert (verdict["code"], _names(verdict)["dcdiag_dc2"]) == ("readback_failed", False), verdict


def test_the_dc_read_body_accepts_a_failed_replications_with_the_row_failing_unchanged(
    one: Server7, tmp_path: Path
) -> None:
    """The measured case: DC2's inbound Schema row fails on every poll,
    unchanged, and the dcdiag fails ``Replications`` on every poll.  The
    op converges on the third poll, where the pass holds a failing row the
    rule accepts (recorded unchanged on the first poll)."""
    failing = _dc_rows_now()
    lines = _dc_dcdiag_failed_replications()
    other = [*lines, "         ......................... BDC2 failed test KnowsOfRoleHolders"]
    fake = dict(_good_fake(), repadmin_polls=[failing, failing, failing])
    fake["dcdiag_polls"] = [{"rc": 0, "lines": other}, {"rc": 0, "lines": other}, {"rc": 0, "lines": lines}]
    output, calls = _run_body(one, tmp_path, "s7-dc", fake, "dc2", DiagWaitSeconds="2")
    assert len([c for c in calls if c.startswith("repadmin")]) >= 3, calls
    assert "3 polls, converged True" in output, output
    assert "old failures confirmed: True" in output, output
    verdict = _verdict(one, "s7-dc", output, "dc2")
    assert _names(verdict)["dcdiag_dc2"] is True, verdict


def test_a_dc_read_with_every_row_clean_and_a_failed_replications_is_readback_failed(
    one: Server7,
) -> None:
    """The measured read of DC2 with every repadmin row clean: the dcdiag
    still fails ``Replications``, and that failure is not accepted: the last
    poll's rows hold no failing row at all."""
    text = _fixture(MEASURED_DC)
    assert DC_SCHEMA_FAILURE in text
    clean = text.replace(DC_SCHEMA_FAILURE, DC_SCHEMA_CLEAN)
    assert clean != text
    verdict = _verdict(one, "s7-dc", clean, "dc2")
    assert (verdict["code"], _names(verdict)["dcdiag_dc2"]) == ("readback_failed", False), verdict


# ---------------------------------------------------------------------------
# DC2's own dcdiag wait: a hard limit, and the token's margin of one pass
# ---------------------------------------------------------------------------


def test_the_dc_read_never_starts_a_pass_after_its_wait(one: Server7, tmp_path: Path) -> None:
    """The wait is a hard limit: no pass starts once it is spent, and the
    sleep between two passes is the shorter of the poll and the time left.
    A pass that starts with seconds left may not end after the limit."""
    fake = dict(_good_fake(), repadmin=_dc_rows_now())
    fake["dcdiag_polls"] = [{"rc": 0, "lines": _dc_dcdiag_failed_replications()}]
    # the fake sleeps what the op asks for, up to the cap
    fake["sleep_cap_ms"] = 60000
    output, calls = _run_body(one, tmp_path, "s7-dc", fake, "dc2", DiagWaitSeconds="3", DiagPollSeconds="6")
    polls = [line for line in output.splitlines() if line.startswith("poll ")]
    assert polls, output
    for line in polls:
        assert int(line.split(", ")[1].split(" ")[0]) < 3, (line, output)
    assert int(output.split("read-back after ")[1].split(" s")[0]) <= 3, output


#: The helper's post-boot grace and its read margin: the time the token has
#: left is its EXP plus the grace less the margin.
GRACE = 900
READ_MARGIN = 120
#: The margin of one pass (a repadmin and a dcdiag) that DC2's own dcdiag
#: wait leaves inside the token's bound.
PASS_MARGIN = 180


@pytest.mark.parametrize(
    ("now", "diag", "read"),
    [
        (BASE, "900", "1800"),
        (BASE + 1500, "900", "1080"),
        (BASE + 1680, "720", "900"),
        (BASE + 2000, "400", "580"),
        (BASE + 2400, "0", "180"),
    ],
)
def test_the_diag_wait_leaves_the_token_a_margin_of_one_pass(
    tmp_path: Path, now: int, diag: str, read: str
) -> None:
    """DC2's own dcdiag waits at most 15 minutes and never past the token
    less the margin of one pass: a pass that starts before the limit may
    end after it.  DC1's own read-back wait is untouched by that margin."""
    left = EXP + GRACE - now - READ_MARGIN
    assert diag == str(max(0, min(900, left - PASS_MARGIN)))
    assert read == str(max(0, min(1800, left)))
    dc1, dc2 = _servers(tmp_path)
    the_plan = _plan()
    if now <= EXP:
        # DC1's own read-back: its wait is the token's time left, and the
        # margin of one pass does not touch it.  A run's window is the
        # token's own, so a request past the EXP is refused and the
        # read-back is not rendered at all.
        _before_7(dc1, the_plan, "dc1")
        _s7(dc1, the_plan, "started", "s7_installed")
        read_back = _call(dc1, the_plan, ops={"s7-read": _ok("s7-read-constructed.txt")}, now=now)
        assert f"$ReadWaitSeconds = '{read}'" in _script(read_back, "s7-read")
    # DC2's own dcdiag: the token's time left less the margin of one pass.
    _before_7(dc2, the_plan, "dc2")
    _s7(dc2, the_plan, "rebooting", "s7_member")
    own = _call(dc2, the_plan, "status", ops={"s7-dc": _ok("s7-dc-constructed.txt")}, boot=BOOT_C, now=now)
    assert f"$DiagWaitSeconds = '{diag}'" in _script(own, "s7-dc")


# ---------------------------------------------------------------------------
# DC2's own read in the SYSTEM task (DESIGN-1.5 point 83)
#
# The helper's key login holds no network credentials: dcdiag's
# KnowsOfRoleHolders and RidManager fail under it with
# "[BDC1] DsBindWithSpnEx() failed with error 5" for the whole wait.  The
# same tests on DC2 run as NT AUTHORITY\SYSTEM (DC2's machine account) and
# pass.  So DC2's own read runs in a one-shot task registered as SYSTEM for
# that one run and removed after it ends.
# ---------------------------------------------------------------------------


def _system_task(server: Server7, *, op: str = "s7-dc", start_at: float | None = 2,
                 run_for: float | None = 10, result: int = 0) -> dict[str, Any]:
    """The SYSTEM task of one op, under the driver of the tests."""
    payload: dict[str, Any] = {
        "mode": "system-task",
        "op": op,
        "fake": {"task": {"start_at": start_at, "run_for": run_for, "result": result, "existing": None,
                          "start_on_disable": False}},
    }
    return server.drive(payload)


def _password_task(server: Server7, *, op: str = "s7-read", start_at: float | None = 2,
                   run_for: float | None = 10, result: int = 0) -> dict[str, Any]:
    """The password task of one op, under the driver of the tests."""
    payload: dict[str, Any] = {
        "mode": "task",
        "op": op,
        "fake": {"task": {"start_at": start_at, "run_for": run_for, "result": result, "existing": None,
                          "start_on_disable": False}},
    }
    return server.drive(payload)


def _registered(out: dict[str, Any]) -> dict[str, Any]:
    calls = [c for c in out["calls"] if c["kind"] == "register"]
    assert len(calls) == 1, out["calls"]
    return calls[0]


def test_the_system_task_is_registered_as_system_with_no_password_and_is_removed_after_it_ends(
    one: Server7,
) -> None:
    """The ruling of 2026-11-23: the task runs as NT AUTHORITY\\SYSTEM (DC2's
    machine account), with the ServiceAccount logon type and the highest run
    level, with no password at all, and it is removed when it ends."""
    out = _system_task(one)
    assert "error" not in out, out
    assert out["task"] == {"outcome": "ended", "result": 0, "found": ""}
    registered = _registered(out)
    assert registered["principal_user"] == "NT AUTHORITY\\SYSTEM", registered
    assert registered["principal_logon_type"] == "ServiceAccount", registered
    assert registered["principal_run_level"] == "Highest", registered
    assert registered["user"] == "", registered
    assert registered["has_password"] is False, registered
    # the password of the build account is never read for this task
    assert [c for c in out["calls"] if c["kind"] == "password"] == []
    # the task is removed when it ends
    assert [c["registered"] for c in out["calls"] if c["kind"] == "unregister"][-1] is True


def test_the_password_task_is_registered_with_the_build_account_and_its_password(one: Server7) -> None:
    """The password task's own registration is unchanged: the user of the
    session and the password of the build account, and no principal."""
    out = _password_task(one)
    assert "error" not in out, out
    registered = _registered(out)
    assert registered["user"] == "NBUILD\\newton-build", registered
    assert registered["has_password"] is True, registered
    assert registered["principal_user"] == "", registered
    assert registered["principal_logon_type"] == "", registered
    assert registered["run_level"] == "Highest", registered
    assert [c for c in out["calls"] if c["kind"] == "password"]


def test_the_stage_7_post_boot_path_runs_dc2s_own_read_in_the_system_task(tmp_path: Path) -> None:
    """DC2's own read (s7-dc) runs in the SYSTEM task, not in the session of
    the status request."""
    _, dc2 = _servers(tmp_path)
    the_plan = _plan()
    _before_7(dc2, the_plan, "dc2")
    _s7(dc2, the_plan, "rebooting", "s7_member", boot=BOOT_B)
    result = _call(dc2, the_plan, "status", ops={"s7-dc": _ok("s7-dc-constructed.txt")}, boot=BOOT_C)
    calls = [c for c in result["calls"] if c["kind"] == "op"]
    assert [c["op"] for c in calls] == ["s7-dc"], result["calls"]
    assert calls[0]["task"] is True, calls[0]
    assert calls[0]["system"] is True, calls[0]
    assert (result["answer"]["ok"], result["answer"]["status"]) == (True, "done"), result


def test_a_status_while_the_dc_read_task_runs_answers_in_flight_and_starts_no_second_task(
    tmp_path: Path,
) -> None:
    """The status request does not hold the session for the whole op: the
    task still runs at the wait, the stage is in flight with no terminal
    entry, and a second status starts no second task."""
    _, dc2 = _servers(tmp_path)
    the_plan = _plan()
    _before_7(dc2, the_plan, "dc2")
    _s7(dc2, the_plan, "rebooting", "s7_member", boot=BOOT_B)
    running = _call(dc2, the_plan, "status", ops={"s7-dc": {"result": -1, "output": "", "outcome": "running"}}, boot=BOOT_C)
    assert (running["answer"]["ok"], running["answer"]["status"]) == (True, "started"), running
    # the entry names the op, so a later status reads its result file
    assert _phases(dc2)[-1] == ("started", "s7_dc")
    again = _call(dc2, the_plan, "status", running=["s7-dc"], boot=BOOT_C)
    assert (again["answer"]["ok"], again["answer"]["status"]) == (True, "started"), again
    assert _ops(again) == []
    assert _phases(dc2)[-1] == ("started", "s7_dc")


@pytest.mark.parametrize("fixture", ["s7-dc-constructed.txt", "s7-dc-measured-schema.txt"])
def test_a_later_status_with_the_result_file_completes_the_stage_with_the_verdict(
    tmp_path: Path, fixture: str
) -> None:
    """The task ended and wrote its result file: the verdict of the op is the
    outcome of the stage, as it is for every other op of the record path."""
    _, dc2 = _servers(tmp_path)
    the_plan = _plan()
    _before_7(dc2, the_plan, "dc2")
    _s7(dc2, the_plan, "started", "s7_dc", boot=BOOT_C)
    done = _call(dc2, the_plan, "status", results={"s7-dc": _ok(fixture)}, boot=BOOT_C)
    assert (done["answer"]["ok"], done["answer"]["status"]) == (True, "done"), done
    assert {"s7_dc", "machine_password", "secure_channel"} <= {c["name"] for c in done["answer"]["checks"]}
    assert _phases(dc2)[-1] == ("done", "s7_dc")


def test_a_later_status_with_a_failing_result_file_stops_the_stage(tmp_path: Path) -> None:
    """The verdict of the op fails: the stage stops with the code of the
    check that failed, as it does for every other op."""
    _, dc2 = _servers(tmp_path)
    the_plan = _plan()
    _before_7(dc2, the_plan, "dc2")
    _s7(dc2, the_plan, "started", "s7_dc", boot=BOOT_C)
    text = _fixture("s7-dc-constructed.txt").replace("pwdLastSet after the reset: 134392457500000000",
                                                      "pwdLastSet after the reset: 134392455248383064")
    failed = _call(dc2, the_plan, "status", results={"s7-dc": {"result": 0, "output": text}}, boot=BOOT_C)
    assert (failed["answer"]["ok"], failed["answer"]["status"], failed["answer"]["code"]) == (
        False, "stopped", "readback_failed"), failed
    assert _phases(dc2)[-1] == ("stopped", "s7_dc")


def test_a_dc_read_task_that_never_starts_stops_the_stage(tmp_path: Path) -> None:
    """The task did not leave 267011 within the start bound: nothing ran, and
    the stage stops as the other task ops do."""
    _, dc2 = _servers(tmp_path)
    the_plan = _plan()
    _before_7(dc2, the_plan, "dc2")
    _s7(dc2, the_plan, "rebooting", "s7_member", boot=BOOT_B)
    result = _call(dc2, the_plan, "status", ops={"s7-dc": {"result": -1, "output": "", "outcome": "not_started"}},
                   boot=BOOT_C)
    assert (result["answer"]["ok"], result["answer"]["status"], result["answer"]["code"]) == (
        False, "stopped", "op_failed"), result
    calls = [c for c in result["calls"] if c["kind"] == "op"]
    assert calls and calls[0]["system"] is True, result["calls"]


def test_a_dc_read_task_that_ends_without_a_result_file_stops_the_stage(tmp_path: Path) -> None:
    """The task ended and the op wrote no result file: it did not run to its
    end, and the stage stops as the other task ops do."""
    _, dc2 = _servers(tmp_path)
    the_plan = _plan()
    _before_7(dc2, the_plan, "dc2")
    _s7(dc2, the_plan, "started", "s7_dc", boot=BOOT_C)
    result = _call(dc2, the_plan, "status", boot=BOOT_C)
    assert (result["answer"]["ok"], result["answer"]["status"], result["answer"]["code"]) == (
        False, "stopped", "op_failed"), result
    assert _phases(dc2)[-1] == ("stopped", "s7_dc")


def test_a_session_dropped_while_the_dc_read_task_runs_is_recorded_from_its_result_file(
    tmp_path: Path,
) -> None:
    """The session drops while the op runs in its task: the entry of the op
    is on the disk already, so a later status reads the result file and
    completes the stage, and starts no second task."""
    _, dc2 = _servers(tmp_path)
    the_plan = _plan()
    _before_7(dc2, the_plan, "dc2")
    _s7(dc2, the_plan, "rebooting", "s7_member", boot=BOOT_B)
    dropped = _call(dc2, the_plan, "status", ops={"s7-dc": {"drop": True, "result": -1, "output": ""}}, boot=BOOT_C)
    assert dropped.get("dropped") is True, dropped
    assert _phases(dc2)[-1] == ("started", "s7_dc")
    done = _call(dc2, the_plan, "status", results={"s7-dc": _ok("s7-dc-constructed.txt")}, boot=BOOT_C)
    assert (done["answer"]["ok"], done["answer"]["status"]) == (True, "done"), done
    assert _ops(done) == []
