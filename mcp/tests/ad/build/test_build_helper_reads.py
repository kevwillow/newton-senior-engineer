"""The helper's DC reads for the checkpoint verify (PLAN-1.5 task 8 part B0;
DESIGN-1.5 "Checkpoints", open point 3 of task 8 and 7 of task 7).

A ``read`` request names one read in an eighth field, ``read``:
``genid`` (the ``msDS-GenerationId`` line of the ``s2-genid`` op),
``showbackup`` (``repadmin /showbackup``) or ``versions`` (``wbadmin get
versions``).  It is taken under the plan token, only for a stage whose
design checkpoint is a DC checkpoint on this server (DC1's 3, 4, 6 and 7)
and only once that stage holds a checkpoint of this plan.  It runs in the
helper's own session, never an op and never a password task, and it
writes nothing to the journal.  The answer carries ``read``: the read's
name, the computer name it ran on, the server's UTC offset in minutes and
the text, in the shapes ``checkpoint.py``'s readers parse (pinned to the
measured bytes of ``fixtures/checkpoints``).

The driver is the one of ``test_build_stages_0_4`` with fakes of the
native reads, the computer name, the UTC offset and ``Get-ADComputer``;
the op runner, the password task and the restart record a call and fail,
so a read that reached one would show.
"""

from __future__ import annotations

import base64
import copy
import json
from pathlib import Path
from typing import Any

import pytest

from newton_mcp.ad.build import checkpoint, plan
from newton_mcp.approve import approval_token
from test_build_stages_0_4 import (  # type: ignore[import-not-found]
    BASE,
    DRIVER,
    EXP,
    KEY_HEX,
    NBF,
    PLAN_INPUTS,
    RUN,
    Server,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "checkpoints"

#: The fakes of the reads.  Each is defined only when the payload holds
#: its value, so a test that leaves one out runs the helper's own.
READ_FAKES = r"""
$script:ReadFake = Get-NewtonField $script:DriverIn.fake 'reads'
function Invoke-NewtonStageOp {
    param([string]$Op, [string]$Script, [bool]$AsTask, [int]$WaitSeconds = -1)
    [void]$script:DriverCalls.Add([ordered]@{ kind = 'op'; op = $Op })
    throw 'a read ran an op'
}
function Invoke-NewtonPasswordTask {
    param([string]$Op, [string]$OpPath, [int]$WaitSeconds = -1)
    [void]$script:DriverCalls.Add([ordered]@{ kind = 'password-task'; op = $Op })
    throw 'a read ran a password task'
}
function Invoke-NewtonRestart {
    [void]$script:DriverCalls.Add([ordered]@{ kind = 'restart' })
    throw 'a read restarted the server'
}
if ($null -ne $script:ReadFake) {
    if ($null -ne (Get-NewtonField $script:ReadFake 'windows')) {
        function Test-NewtonWindowsHost { return [bool]$script:ReadFake.windows }
    }
    function Import-Module {
        param([string]$Name, $ErrorAction)
        [void]$script:DriverCalls.Add([ordered]@{ kind = 'import'; name = $Name })
    }
    function Invoke-NewtonNativeRead {
        param([string]$Exe, [string[]]$Arguments)
        [void]$script:DriverCalls.Add([ordered]@{ kind = 'native'; exe = $Exe; arguments = @($Arguments) })
        $one = Get-NewtonField $script:ReadFake.native $Exe
        if ($null -eq $one) { throw ('the fake holds no output for ' + $Exe) }
        return @{ exit = [int]$one.exit; lines = [string[]]@($one.lines) }
    }
    if ($null -ne (Get-NewtonField $script:ReadFake 'computer')) {
        function Get-NewtonComputerName { return [string]$script:ReadFake.computer }
    }
    if ($null -ne (Get-NewtonField $script:ReadFake 'offset')) {
        function Get-NewtonUtcOffsetMinutes { return $script:ReadFake.offset }
    }
    function Get-ADComputer {
        param([string]$Identity, [string[]]$Properties, $ErrorAction)
        [void]$script:DriverCalls.Add([ordered]@{ kind = 'get-adcomputer'; identity = $Identity; properties = @($Properties) })
        $one = $script:ReadFake.adcomputer
        if ($null -eq $one) { throw 'Get-ADComputer: the directory did not answer' }
        $bytes = $null
        if ($null -ne $one.genid) { $bytes = [byte[]]@($one.genid | ForEach-Object { [byte]$_ }) }
        return [pscustomobject]@{ DistinguishedName = [string]$one.dn; 'msDS-GenerationId' = $bytes }
    }
}
"""

READ_DRIVER = DRIVER.replace("$result = [ordered]@{}", READ_FAKES + "\n$result = [ordered]@{}", 1)
assert READ_DRIVER != DRIVER

#: The measured bytes of msDS-GenerationId on BUILD1 (MEASURED-1.5
#: "Checkpoints on BUILD1, 2026-11-14").
GENID = bytes.fromhex("65af35ee9de38e46")
DC1_DN = "CN=BDC1,OU=Domain Controllers,DC=build,DC=newton,DC=test"

CP = "m8-dc1"


class ReadServer(Server):
    """The install root of BUILD1, driven with the read fakes."""

    def __init__(self, root: Path, device: str = "build1") -> None:
        super().__init__(root)
        (root / "device.txt").write_text(device + "\n", encoding="ascii")
        self.driver.write_text(READ_DRIVER, encoding="utf-8")


@pytest.fixture
def server(tmp_path: Path) -> ReadServer:
    return ReadServer(tmp_path / "install")


def _two_server_plan() -> dict[str, Any]:
    inputs = copy.deepcopy(PLAN_INPUTS)
    dc2 = copy.deepcopy(inputs["servers"][0])
    dc2.update(
        {
            "device": "build2",
            "role": "dc2",
            "hostname": "BDC2",
            "ip": "192.0.2.42",
            "vmgenid": "91824320-4ff7-45cb-906f-7104661ec799",
        }
    )
    inputs["servers"].append(dc2)
    return plan.plan_build(inputs)


def _lines(name: str) -> list[str]:
    """The lines of a measured read as PowerShell hands them on: one per
    line of the program's output, the blank ones included."""
    text = (FIXTURES / name).read_text(encoding="utf-8")
    assert text.endswith("\n")
    return text[:-1].split("\n")


def _seed_checkpointed(server: Server, the_plan: dict[str, Any], stage: str) -> None:
    """The journal of DC1 up to ``stage``, which holds its checkpoint."""
    digest = plan.digest(the_plan)
    graph = plan.stage_graph(the_plan, "dc1")
    records: list[dict[str, Any]] = []
    for earlier in graph:
        if earlier == stage:
            break
        records.append({"stage": earlier, "state": "started", "digest": digest})
        records.append({"stage": earlier, "state": "done", "digest": digest})
    records.append({"stage": stage, "state": "checkpointed", "digest": digest, "checkpoint": CP})
    server.seed(records)


def _read_request(
    the_plan: dict[str, Any],
    stage: str,
    read: str | None,
    *,
    action: str = "read",
    signed: str | None = None,
    nbf: int = NBF,
    exp: int = EXP,
    extra: dict[str, Any] | None = None,
) -> str:
    digest = plan.digest(the_plan)
    request: dict[str, Any] = {
        "run": RUN,
        "plan": base64.b64encode(plan.canonical_bytes(the_plan)).decode("ascii"),
        "stage": stage,
        "action": action,
        "token": approval_token(KEY_HEX, digest if signed is None else signed, nbf, exp),
        "nbf": nbf,
        "exp": exp,
    }
    if read is not None:
        request["read"] = read
    if extra:
        request.update(extra)
    return json.dumps(request)


def _fakes(**over: Any) -> dict[str, Any]:
    reads: dict[str, Any] = {
        "windows": True,
        "computer": "BDC1",
        "offset": 0,
        "adcomputer": {"dn": DC1_DN, "genid": list(GENID)},
        "native": {
            "repadmin.exe": {"exit": 0, "lines": _lines("repadmin-showbackup-ac.txt")},
            "wbadmin.exe": {"exit": 0, "lines": _lines("wbadmin-versions-dc-ac.txt")},
        },
    }
    reads.update(over)
    return reads


def _drive(server: Server, request: str, reads: dict[str, Any] | None = None, *, now: int = BASE) -> dict[str, Any]:
    payload = {
        "mode": "request",
        "request": request,
        "fake": {
            "ops": {},
            "groups": [],
            "directory": True,
            "restart": False,
            "results": {},
            "running": [],
            "reads": _fakes() if reads is None else reads,
        },
    }
    return server.drive(payload, now=now)


def _no_writes(result: dict[str, Any]) -> None:
    kinds = {call["kind"] for call in result["calls"]}
    assert not kinds & {"op", "password-task", "restart", "secret"}, result["calls"]


# ---------------------------------------------------------------------------
# the three reads, in the measured shapes
# ---------------------------------------------------------------------------


def test_the_genid_read_answers_the_s2_genid_line_of_this_dc(server: ReadServer) -> None:
    the_plan = _two_server_plan()
    _seed_checkpointed(server, the_plan, "3")
    before = server.journal()
    result = _drive(server, _read_request(the_plan, "3", "genid"))
    answer = result["answer"]
    assert answer["ok"] is True, result
    assert answer["status"] == "done"
    assert set(answer) == {"ok", "status", "code", "checks", "read"}
    assert answer["read"] == {
        "name": "genid",
        "computer": "BDC1",
        "utc_offset_minutes": 0,
        "text": f"msDS-GenerationId on {DC1_DN}: present, 8 bytes, 65af35ee9de38e46\n",
    }
    # The reader of checkpoint.py takes it whole, and its line is the
    # line of the measured s2-genid op.
    assert checkpoint.genid_present(answer["read"]["text"], hostname="BDC1") is True
    measured = (Path(__file__).resolve().parent / "fixtures" / "stages_0_4" / "s2-genid-present.txt").read_text()
    line = answer["read"]["text"].rstrip("\n")
    assert line.rsplit(", ", 1)[0] in measured
    lookups = [c for c in result["calls"] if c["kind"] == "get-adcomputer"]
    assert lookups == [{"kind": "get-adcomputer", "identity": "BDC1", "properties": ["msDS-GenerationId"]}]
    assert server.journal() == before
    _no_writes(result)


def test_the_genid_read_of_a_dc_without_the_attribute_says_absent(server: ReadServer) -> None:
    the_plan = _two_server_plan()
    _seed_checkpointed(server, the_plan, "4")
    result = _drive(server, _read_request(the_plan, "4", "genid"), _fakes(adcomputer={"dn": DC1_DN, "genid": None}))
    text = result["answer"]["read"]["text"]
    assert text == f"msDS-GenerationId on {DC1_DN}: absent\n"
    assert checkpoint.genid_present(text, hostname="BDC1") is False


def test_the_showbackup_read_answers_repadmin_bytes_and_the_offset(server: ReadServer) -> None:
    the_plan = _two_server_plan()
    _seed_checkpointed(server, the_plan, "6")
    result = _drive(server, _read_request(the_plan, "6", "showbackup"), _fakes(offset=-300))
    read = result["answer"]["read"]
    assert read["name"] == "showbackup"
    assert read["utc_offset_minutes"] == -300
    assert read["text"] == (FIXTURES / "repadmin-showbackup-ac.txt").read_text(encoding="utf-8")
    parsed = checkpoint.parse_showbackup(read["text"])
    assert len(parsed) == 5 and all(parsed.values())
    natives = [c for c in result["calls"] if c["kind"] == "native"]
    assert natives == [{"kind": "native", "exe": "repadmin.exe", "arguments": ["/showbackup"]}]
    _no_writes(result)


def test_the_versions_read_answers_wbadmin_bytes_the_computer_and_the_offset(server: ReadServer) -> None:
    the_plan = _two_server_plan()
    _seed_checkpointed(server, the_plan, "7")
    result = _drive(server, _read_request(the_plan, "7", "versions"), _fakes(offset=60))
    read = result["answer"]["read"]
    assert read["name"] == "versions"
    assert read["computer"] == "BDC1"
    assert read["utc_offset_minutes"] == 60
    assert read["text"] == (FIXTURES / "wbadmin-versions-dc-ac.txt").read_text(encoding="utf-8")
    assert len(checkpoint.parse_wbadmin_versions(read["text"])) == 2
    natives = [c for c in result["calls"] if c["kind"] == "native"]
    assert natives == [{"kind": "native", "exe": "wbadmin.exe", "arguments": ["get", "versions"]}]
    _no_writes(result)


def test_the_helper_s_own_utc_offset_is_whole_minutes_in_range(server: ReadServer) -> None:
    """Without the fake the helper's own offset is read: an int, -1440 < x < 1440."""
    the_plan = _two_server_plan()
    _seed_checkpointed(server, the_plan, "3")
    reads = _fakes()
    del reads["offset"]
    result = _drive(server, _read_request(the_plan, "3", "showbackup"), reads)
    offset = result["answer"]["read"]["utc_offset_minutes"]
    assert isinstance(offset, int) and not isinstance(offset, bool)
    assert -1440 < offset < 1440


@pytest.mark.parametrize("read", ["showbackup", "versions"])
def test_a_native_read_that_fails_is_refused_readback_failed(server: ReadServer, read: str) -> None:
    the_plan = _two_server_plan()
    _seed_checkpointed(server, the_plan, "3")
    exe = "repadmin.exe" if read == "showbackup" else "wbadmin.exe"
    native = {exe: {"exit": 1, "lines": ["ERROR - No backup was found."]}}
    result = _drive(server, _read_request(the_plan, "3", read), _fakes(native=native))
    assert result["answer"]["ok"] is False
    assert result["answer"]["code"] == "readback_failed"
    assert "read" not in result["answer"]


def test_a_genid_read_whose_directory_fails_is_refused_readback_failed(server: ReadServer) -> None:
    the_plan = _two_server_plan()
    _seed_checkpointed(server, the_plan, "3")
    result = _drive(server, _read_request(the_plan, "3", "genid"), _fakes(adcomputer=None))
    assert result["answer"]["code"] == "readback_failed"


@pytest.mark.parametrize("computer", ["", "BDC1 ", "B.DC1", "a" * 16, "BDC1\nX"])
def test_a_computer_name_outside_the_grammar_is_refused(server: ReadServer, computer: str) -> None:
    the_plan = _two_server_plan()
    _seed_checkpointed(server, the_plan, "3")
    result = _drive(server, _read_request(the_plan, "3", "versions"), _fakes(computer=computer))
    assert result["answer"]["code"] == "readback_failed"


@pytest.mark.parametrize("offset", [1440, -1440, 100000, "0", True, 1.5])
def test_an_offset_that_is_not_whole_minutes_in_range_is_refused(server: ReadServer, offset: Any) -> None:
    the_plan = _two_server_plan()
    _seed_checkpointed(server, the_plan, "3")
    result = _drive(server, _read_request(the_plan, "3", "showbackup"), _fakes(offset=offset))
    assert result["answer"]["code"] == "readback_failed", result


def test_a_read_bigger_than_the_helper_answers_is_refused(server: ReadServer) -> None:
    the_plan = _two_server_plan()
    _seed_checkpointed(server, the_plan, "3")
    native = {"repadmin.exe": {"exit": 0, "lines": ["x" * 1000] * 70}}
    result = _drive(server, _read_request(the_plan, "3", "showbackup"), _fakes(native=native))
    assert result["answer"]["code"] == "readback_failed", result


def test_reads_run_only_under_windows(server: ReadServer) -> None:
    the_plan = _two_server_plan()
    _seed_checkpointed(server, the_plan, "3")
    result = _drive(server, _read_request(the_plan, "3", "genid"), _fakes(windows=False))
    assert result["answer"]["code"] == "schema"
    assert not [c for c in result["calls"] if c["kind"] in ("native", "get-adcomputer")]


# ---------------------------------------------------------------------------
# what a read request may be
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("read", ["", "GENID", "genid ", "dcdiag", "repadmin", "status", 1, None, ["genid"]])
def test_a_read_outside_the_three_is_schema(server: ReadServer, read: Any) -> None:
    the_plan = _two_server_plan()
    _seed_checkpointed(server, the_plan, "3")
    request = json.loads(_read_request(the_plan, "3", "genid"))
    request["read"] = read
    result = _drive(server, json.dumps(request))
    assert result["answer"]["code"] == "schema", result
    assert not [c for c in result["calls"] if c["kind"] in ("native", "get-adcomputer")]


def test_a_read_request_without_its_read_is_schema(server: ReadServer) -> None:
    the_plan = _two_server_plan()
    _seed_checkpointed(server, the_plan, "3")
    result = _drive(server, _read_request(the_plan, "3", None))
    assert result["answer"]["code"] == "schema"


@pytest.mark.parametrize("action", ["run", "status", "checkpoint"])
def test_only_a_read_request_names_a_read(server: ReadServer, action: str) -> None:
    the_plan = _two_server_plan()
    _seed_checkpointed(server, the_plan, "3")
    before = server.journal()
    result = _drive(server, _read_request(the_plan, "3", "genid", action=action))
    assert result["answer"]["code"] == "schema"
    assert server.journal() == before


def test_a_read_request_naming_a_checkpoint_is_schema(server: ReadServer) -> None:
    the_plan = _two_server_plan()
    _seed_checkpointed(server, the_plan, "3")
    result = _drive(server, _read_request(the_plan, "3", "genid", extra={"checkpoint": CP}))
    assert result["answer"]["code"] == "schema"


@pytest.mark.parametrize("stage", ["0", "1", "2", "5", "8", "9", "10"])
def test_a_read_for_a_stage_without_a_dc_checkpoint_is_schema(server: ReadServer, stage: str) -> None:
    """DC1's DC checkpoints are 3, 4, 6 and 7; stage 2's is a workgroup one."""
    the_plan = _two_server_plan()
    _seed_checkpointed(server, the_plan, "3")
    result = _drive(server, _read_request(the_plan, stage, "genid"))
    assert result["answer"]["code"] == "schema", result
    assert not [c for c in result["calls"] if c["kind"] in ("native", "get-adcomputer")]


def test_dc2_takes_no_dc_read_its_stage_7_checkpoint_is_a_workgroup_one(tmp_path: Path) -> None:
    server = ReadServer(tmp_path / "install", device="build2")
    the_plan = _two_server_plan()
    digest = plan.digest(the_plan)
    server.seed(
        [
            {"stage": "0", "state": "done", "digest": digest},
            {"stage": "1", "state": "done", "digest": digest},
            {"stage": "7", "state": "checkpointed", "digest": digest, "checkpoint": "m8-dc2"},
        ]
    )
    result = _drive(server, _read_request(the_plan, "7", "genid"), _fakes(computer="BDC2"))
    assert result["answer"]["code"] == "schema", result


def test_a_read_before_the_stage_holds_a_checkpoint_is_out_of_order(server: ReadServer) -> None:
    the_plan = _two_server_plan()
    _seed_checkpointed(server, the_plan, "3")
    result = _drive(server, _read_request(the_plan, "4", "genid"))
    assert result["answer"]["code"] == "out_of_order", result
    assert not [c for c in result["calls"] if c["kind"] in ("native", "get-adcomputer")]


def test_a_read_under_the_stage_token_is_bad_token(server: ReadServer) -> None:
    """The read is under the plan token; the owner's stage token opens none."""
    the_plan = _two_server_plan()
    _seed_checkpointed(server, the_plan, "3")
    signed = plan.stage_digest(plan.digest(the_plan), "3", CP)
    result = _drive(server, _read_request(the_plan, "3", "genid", signed=signed))
    assert result["answer"]["code"] == "bad_token"


def test_a_read_with_another_key_s_token_is_bad_token(server: ReadServer) -> None:
    the_plan = _two_server_plan()
    _seed_checkpointed(server, the_plan, "3")
    request = json.loads(_read_request(the_plan, "3", "genid"))
    request["token"] = approval_token("e5" * 32, plan.digest(the_plan), NBF, EXP)
    result = _drive(server, json.dumps(request))
    assert result["answer"]["code"] == "bad_token"


def test_a_read_past_the_plan_token_s_exp_is_expired(server: ReadServer) -> None:
    the_plan = _two_server_plan()
    _seed_checkpointed(server, the_plan, "3")
    before = server.journal()
    result = _drive(server, _read_request(the_plan, "3", "genid"), now=EXP + 1)
    assert result["answer"]["code"] == "expired"
    assert server.journal() == before
    assert not [c for c in result["calls"] if c["kind"] in ("native", "get-adcomputer")]


def test_a_read_before_the_plan_token_s_nbf_is_expired(server: ReadServer) -> None:
    the_plan = _two_server_plan()
    _seed_checkpointed(server, the_plan, "3")
    result = _drive(server, _read_request(the_plan, "3", "genid"), now=NBF - 1)
    assert result["answer"]["code"] == "expired"


def test_a_read_of_another_plan_is_plan_mismatch(server: ReadServer) -> None:
    the_plan = _two_server_plan()
    _seed_checkpointed(server, the_plan, "3")
    inputs = copy.deepcopy(PLAN_INPUTS)
    inputs["domain"]["owner_admin"] = "other-admin"
    dc2 = copy.deepcopy(inputs["servers"][0])
    dc2.update(
        {
            "device": "build2",
            "role": "dc2",
            "hostname": "BDC2",
            "ip": "192.0.2.42",
            "vmgenid": "91824320-4ff7-45cb-906f-7104661ec799",
        }
    )
    inputs["servers"].append(dc2)
    other = plan.plan_build(inputs)
    result = _drive(server, _read_request(other, "3", "genid"))
    assert result["answer"]["code"] == "plan_mismatch", result


# ---------------------------------------------------------------------------
# the bytes of the S4U key login (MEASURED-1.5 "Stage 7 on BUILD1 and
# BUILD2, 2026-11-15", the B0 reads)
# ---------------------------------------------------------------------------


def test_the_s4u_key_login_s_showbackup_is_the_measured_shape(server: ReadServer) -> None:
    """repadmin /showbackup over the newton-build key login, before any
    backup: byte for byte the Administrator read of task 7, and the
    helper's text of it parses as five partitions never backed up."""
    s4u = (FIXTURES / "repadmin-showbackup-s4u-before.txt").read_text(encoding="utf-8")
    assert s4u == (FIXTURES / "repadmin-showbackup-before.txt").read_text(encoding="utf-8")
    the_plan = _two_server_plan()
    _seed_checkpointed(server, the_plan, "3")
    native = {"repadmin.exe": {"exit": 0, "lines": _lines("repadmin-showbackup-s4u-before.txt")}}
    result = _drive(server, _read_request(the_plan, "3", "showbackup"), _fakes(native=native))
    text = result["answer"]["read"]["text"]
    assert text == s4u
    parsed = checkpoint.parse_showbackup(text)
    assert len(parsed) == 5 and all(v is None for v in parsed.values())
    assert checkpoint.dsa_signatures_no_older(checkpoint.ShowbackupRead(text, 0), checkpoint._bound(NBF)) is False  # noqa: SLF001


def test_the_measured_no_backup_answer_of_wbadmin_is_refused(server: ReadServer) -> None:
    """wbadmin get versions over the key login with no backup: exit -2
    and the 'No backup was found' text (measured); the read is refused."""
    the_plan = _two_server_plan()
    _seed_checkpointed(server, the_plan, "3")
    native = {"wbadmin.exe": {"exit": -2, "lines": _lines("wbadmin-versions-s4u-none.txt")}}
    result = _drive(server, _read_request(the_plan, "3", "versions"), _fakes(native=native))
    assert result["answer"]["code"] == "readback_failed"
    assert "ERROR - No backup was found." in (FIXTURES / "wbadmin-versions-s4u-none.txt").read_text()
