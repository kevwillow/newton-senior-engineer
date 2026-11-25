"""The DC reads of a checkpoint verify through the helper transport
(PLAN-1.5 task 8 part B0; DESIGN-1.5 open point 3 of task 8 and 7 of task
7).

``transport.HelperDcReads`` is what the build config's real adapters read
``msDS-GenerationId``, ``repadmin /showbackup`` and ``wbadmin get
versions`` with: one ``read`` request of the helper per read, under the
server's plan token, for the stage being verified.  The approval and the
runner open the read context of a server (its run, the plan bytes, the plan
token and its window, the stage) before they verify; without it every read
fails closed.  An answer whose computer is not the plan's hostname, whose
offset is not whole minutes in range, or that is not the read asked for is
unverified.  No read request holds anything but the fields of the contract.
"""

from __future__ import annotations

import base64
import io
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from newton_mcp import approve
from newton_mcp.ad.build import checkpoint, plan, transport
from newton_mcp.ad.build import config as build_config
from test_build_approve import (  # type: ignore[import-not-found]
    CHECKPOINT_ID,
    CHECKPOINT_NAME,
    PASSPHRASE,
    PLAN_ID,
    _stage_approval_path,
    _write_run_state,
    built_plan,  # noqa: F401  (fixtures)
    state_dir,  # noqa: F401
    stored_plan,  # noqa: F401
)

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "checkpoints"
RUN = "c3" * 16
PLAN_BYTES = b"newton-ad-build-v1\nx=y\n"
TOKEN = "d4" * 32
NBF = 1797000000
EXP = NBF + 21600

SERVER = {"device": "build1", "role": "dc1", "hostname": "BDC1", "checkpoint": "wbadmin"}
GENID_TEXT = "msDS-GenerationId on CN=BDC1,OU=Domain Controllers,DC=build,DC=newton,DC=test: present, 8 bytes, 65af35ee9de38e46\n"


def _fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def _read_answer(name: str, text: str, *, computer: str = "BDC1", offset: Any = 0, **over: Any) -> dict[str, Any]:
    read = {"name": name, "computer": computer, "utc_offset_minutes": offset, "text": text}
    read.update(over)
    return {"ok": True, "status": "done", "code": "", "checks": [], "read": read}


class ReadTransport:
    """A helper transport: a status answers the completions, a read answers
    from ``reads`` by name.  The requests are recorded."""

    def __init__(self, reads: dict[str, Any] | None = None, completed: dict[str, int] | None = None) -> None:
        self.reads = reads or {}
        self.completed = completed or {}
        self.requests: list[tuple[str, dict[str, Any]]] = []

    def send(self, device: str, request: dict[str, Any]) -> dict[str, Any]:
        self.requests.append((device, dict(request)))
        if request["action"] == "status":
            return {"ok": True, "status": "done", "code": "", "checks": [], "completed": dict(self.completed)}
        answer = self.reads[request["read"]]
        if isinstance(answer, Exception):
            raise answer
        return transport.parse_answer(json.dumps(answer), action="read")


def _opened(reads: transport.HelperDcReads, device: str = "build1", stage: str = "7") -> None:
    reads.open(device, run=RUN, plan_bytes=PLAN_BYTES, token=TOKEN, nbf=NBF, exp=EXP, stage=stage)


# ---------------------------------------------------------------------------
# the request and the answer of the contract
# ---------------------------------------------------------------------------


def test_a_read_request_holds_the_contract_fields_and_its_read() -> None:
    request = transport.helper_request(
        run=RUN, plan_bytes=PLAN_BYTES, stage="3", action="read", token=TOKEN, nbf=NBF, exp=EXP, read="genid"
    )
    assert request == {
        "run": RUN,
        "plan": base64.b64encode(PLAN_BYTES).decode("ascii"),
        "stage": "3",
        "action": "read",
        "token": TOKEN,
        "nbf": NBF,
        "exp": EXP,
        "read": "genid",
    }


@pytest.mark.parametrize(
    ("action", "read", "cp"),
    [
        ("read", None, None),
        ("read", "dcdiag", None),
        ("read", "GENID", None),
        ("status", "genid", None),
        ("checkpoint", "genid", "m8-dc1"),
        ("read", "genid", "m8-dc1"),
    ],
)
def test_a_read_request_the_helper_would_refuse_is_never_built(action: str, read: Any, cp: Any) -> None:
    with pytest.raises(ValueError):
        transport.helper_request(
            run=RUN, plan_bytes=PLAN_BYTES, stage="3", action=action, token=TOKEN, nbf=NBF, exp=EXP,
            read=read, checkpoint=cp,
        )


def test_the_answer_of_a_read_carries_its_read() -> None:
    answer = transport.parse_answer(json.dumps(_read_answer("genid", GENID_TEXT)), action="read")
    assert answer["read"]["text"] == GENID_TEXT


@pytest.mark.parametrize(
    "answer",
    [
        {"ok": True, "status": "done", "code": "", "checks": []},
        _read_answer("genid", GENID_TEXT, extra="x"),
        {**_read_answer("genid", GENID_TEXT), "completed": {}},
        {"ok": True, "status": "done", "code": "", "checks": [], "read": "text"},
        _read_answer("genid", 5),
        _read_answer("genid", GENID_TEXT, offset=True),
        _read_answer("genid", GENID_TEXT, offset=1.5),
        _read_answer("genid", GENID_TEXT, computer=None),
    ],
)
def test_a_read_answer_outside_the_contract_is_invalid(answer: dict[str, Any]) -> None:
    with pytest.raises(transport.HelperAnswerInvalid):
        transport.parse_answer(json.dumps(answer), action="read")


def test_only_a_read_answer_carries_a_read() -> None:
    with pytest.raises(transport.HelperAnswerInvalid):
        transport.parse_answer(json.dumps(_read_answer("genid", GENID_TEXT)), action="status")


# ---------------------------------------------------------------------------
# HelperDcReads
# ---------------------------------------------------------------------------


def test_a_read_without_an_open_context_fails_closed_and_sends_nothing() -> None:
    fake = ReadTransport({"genid": _read_answer("genid", GENID_TEXT)})
    reads = transport.HelperDcReads(fake)
    with pytest.raises(checkpoint.CheckpointUnverified):
        reads.read_genid(SERVER)
    assert fake.requests == []


def test_the_genid_read_sends_one_read_under_the_plan_token_for_the_stage() -> None:
    fake = ReadTransport({"genid": _read_answer("genid", GENID_TEXT)})
    reads = transport.HelperDcReads(fake)
    _opened(reads, stage="4")
    assert reads.read_genid(SERVER) == GENID_TEXT
    assert fake.requests == [
        (
            "build1",
            {
                "run": RUN,
                "plan": base64.b64encode(PLAN_BYTES).decode("ascii"),
                "stage": "4",
                "action": "read",
                "token": TOKEN,
                "nbf": NBF,
                "exp": EXP,
                "read": "genid",
            },
        )
    ]


def test_the_showbackup_read_answers_its_text_and_the_offset() -> None:
    text = _fixture("repadmin-showbackup-ac.txt")
    fake = ReadTransport({"showbackup": _read_answer("showbackup", text, offset=-300)})
    reads = transport.HelperDcReads(fake)
    _opened(reads)
    assert reads.read_showbackup(SERVER) == checkpoint.ShowbackupRead(text, -300)


def test_the_versions_read_answers_the_computer_the_text_and_the_offset() -> None:
    text = _fixture("wbadmin-versions-dc-ac.txt")
    fake = ReadTransport({"versions": _read_answer("versions", text, computer="bdc1", offset=60)})
    reads = transport.HelperDcReads(fake)
    _opened(reads)
    assert reads.read_versions(SERVER) == checkpoint.WbadminRead("bdc1", text, 60)


@pytest.mark.parametrize(
    "answer",
    [
        _read_answer("genid", GENID_TEXT, computer="BDC2"),
        _read_answer("showbackup", GENID_TEXT),
        _read_answer("genid", GENID_TEXT, offset=1440),
        _read_answer("genid", GENID_TEXT, offset=-1440),
        {"ok": False, "status": "refused", "code": "readback_failed", "checks": []},
        {"ok": True, "status": "checkpointed", "code": "", "checks": [], "read": _read_answer("genid", GENID_TEXT)["read"]},
        transport.HelperUnavailable("the build helper did not answer"),
        transport.HelperAnswerInvalid("no"),
    ],
)
def test_a_read_that_is_not_this_dc_s_answer_is_unverified(answer: Any) -> None:
    fake = ReadTransport({"genid": answer})
    reads = transport.HelperDcReads(fake)
    _opened(reads)
    with pytest.raises(checkpoint.CheckpointUnverified):
        reads.read_genid(SERVER)


def test_a_context_opened_for_one_server_reads_nothing_for_another() -> None:
    fake = ReadTransport({"genid": _read_answer("genid", GENID_TEXT, computer="BDC2")})
    reads = transport.HelperDcReads(fake)
    _opened(reads, device="build1")
    with pytest.raises(checkpoint.CheckpointUnverified):
        reads.read_genid({**SERVER, "device": "build2", "hostname": "BDC2"})
    assert fake.requests == []


def test_a_closed_context_reads_nothing() -> None:
    fake = ReadTransport({"genid": _read_answer("genid", GENID_TEXT)})
    reads = transport.HelperDcReads(fake)
    _opened(reads)
    reads.close("build1")
    with pytest.raises(checkpoint.CheckpointUnverified):
        reads.read_genid(SERVER)


# ---------------------------------------------------------------------------
# the config's real adapters read through the helper
# ---------------------------------------------------------------------------


def _config(tmp_path: Path) -> build_config.BuildConfig:
    return build_config.parse_config(
        {
            "version": 1,
            "servers": {
                "build1": {"host": "192.0.2.11", "port": 22, "key_file": f"{tmp_path}/k", "known_hosts": f"{tmp_path}/kh"},
            },
        }
    )


def test_the_config_s_wbadmin_adapter_verifies_a_dc_checkpoint_through_the_helper(tmp_path: Path) -> None:
    """DC1's stage 7 on wbadmin: the all-critical version of the measured
    read (Bare Metal Recovery) and msDS-GenerationId, both read through
    the helper transport."""
    fake = ReadTransport(
        {
            "versions": _read_answer("versions", _fixture("wbadmin-versions-dc-ac.txt")),
            "genid": _read_answer("genid", GENID_TEXT),
        }
    )
    adapters = build_config.build_adapters(_config(tmp_path), transport=fake)
    adapters.open_reads("build1", run=RUN, plan_bytes=PLAN_BYTES, token=TOKEN, nbf=NBF, exp=EXP, stage="7")
    bound = int(datetime(2026, 11, 14, 7, 30, tzinfo=timezone.utc).timestamp())
    cp = {"name": "wbadmin-build1-dc", "id": "11/14/2026-07:32"}
    assert adapters.verify(SERVER, cp, "dc", stage="7", not_before=bound) is True
    assert [r["read"] for _, r in fake.requests] == ["versions", "genid"]
    for _, request in fake.requests:
        assert set(request) == {"run", "plan", "stage", "action", "token", "nbf", "exp", "read"}


def test_the_config_s_adapters_without_the_transport_still_fail_closed(tmp_path: Path) -> None:
    adapters = build_config.build_adapters(_config(tmp_path))
    cp = {"name": "wbadmin-build1-dc", "id": "11/14/2026-07:32"}
    with pytest.raises(checkpoint.CheckpointUnverified):
        adapters.verify(SERVER, cp, "dc", stage="7", not_before=NBF)


def test_the_config_wires_every_real_adapter_to_the_helper_reads(tmp_path: Path) -> None:
    fake = ReadTransport()
    adapters = build_config.build_adapters(_config(tmp_path), transport=fake)
    reads = adapters.reads
    assert isinstance(reads, transport.HelperDcReads)
    by_method = adapters._by_method  # noqa: SLF001  (the wiring is what this test pins)
    assert by_method["proxmox"]._read_genid == reads.read_genid  # noqa: SLF001
    assert by_method["hyperv"]._read_genid == reads.read_genid  # noqa: SLF001
    assert by_method["hyperv"]._read_showbackup == reads.read_showbackup  # noqa: SLF001
    assert by_method["wbadmin"]._read_versions == reads.read_versions  # noqa: SLF001
    assert by_method["wbadmin"]._read_genid == reads.read_genid  # noqa: SLF001


def test_the_wbadmin_backup_itself_is_still_not_built(tmp_path: Path) -> None:
    """Task 7 open point 2: the plan holds no backup target volume."""
    adapters = build_config.build_adapters(_config(tmp_path), transport=ReadTransport())
    with pytest.raises(checkpoint.CheckpointUnverified):
        adapters.checkpoint(SERVER, "dc")


# ---------------------------------------------------------------------------
# the stage approval opens the read context before it verifies
# ---------------------------------------------------------------------------


def _hv_dc_adapters(reads: transport.HelperDcReads) -> checkpoint.CheckpointAdapters:
    listing = json.dumps(
        [{"name": CHECKPOINT_NAME, "id": CHECKPOINT_ID, "created": "2026-12-31T23:50:00Z", "vm": "DC1", "checkpoint_type": "ProductionOnly"}]
    )
    hyperv = checkpoint.HyperVAdapter(
        {"build1": checkpoint.HyperVTarget(ssh=("ssh", "hv@hvhost.example.test"), vm="DC1")},
        run=lambda argv: (0, listing),
        read_genid=reads.read_genid,
        read_showbackup=reads.read_showbackup,
    )
    return checkpoint.CheckpointAdapters({"hyperv": hyperv}, reads=reads)


#: repadmin /showbackup of the measured shape, the backup after the
#: checkpoint above (2027-01-01 00:01 UTC on a UTC DC).
SHOWBACKUP = _fixture("repadmin-showbackup-ac.txt").replace("DC=build,DC=newton,DC=test", "DC=ad,DC=example,DC=test").replace(
    "2026-11-14 07:33:25", "2027-01-01 00:01:00"
)
DC1_GENID = "msDS-GenerationId on CN=DC1,OU=Domain Controllers,DC=ad,DC=example,DC=test: present, 8 bytes, 65af35ee9de38e46\n"


def _approve_dc_stage(monkeypatch: pytest.MonkeyPatch, fake: ReadTransport, reads: transport.HelperDcReads) -> int:
    monkeypatch.setattr(approve, "_getpass", lambda prompt: PASSPHRASE)
    monkeypatch.setattr("sys.stdin", io.StringIO(f"approve {PLAN_ID[:8]}\n"))
    assert approve.approve_ad_build(PLAN_ID, now=datetime(2026, 12, 31, 22, tzinfo=timezone.utc)) == 0
    monkeypatch.setattr("sys.stdin", io.StringIO(f"approve stage 3 of {PLAN_ID[:8]}\n"))
    return approve.approve_ad_build_stage(
        PLAN_ID, "3", verifier=_hv_dc_adapters(reads), transport=fake, now=datetime(2027, 1, 1, 0, 5, tzinfo=timezone.utc)
    )


def _dc_run_state(state_dir: Path, built_plan: dict[str, Any]) -> None:
    servers = {
        "build1": {
            "stage": "3",
            "state": "stopped_for_approval",
            "checkpoint": {"name": CHECKPOINT_NAME, "id": CHECKPOINT_ID},
            "checkpoint_kind": "dc",
        }
    }
    _write_run_state(state_dir, built_plan, stage="3", servers=servers)


def test_the_stage_approval_verifies_a_dc_checkpoint_through_the_helper_reads(
    stored_plan: Path, state_dir: Path, built_plan: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    _dc_run_state(state_dir, built_plan)
    done_2 = int(datetime(2026, 12, 31, 23, 40, tzinfo=timezone.utc).timestamp())
    fake = ReadTransport(
        {
            "showbackup": _read_answer("showbackup", SHOWBACKUP, computer="DC1"),
            "genid": _read_answer("genid", DC1_GENID, computer="DC1"),
        },
        completed={"0": done_2 - 600, "1": done_2 - 300, "2": done_2},
    )
    reads = transport.HelperDcReads(fake)
    assert _approve_dc_stage(monkeypatch, fake, reads) == 0
    assert _stage_approval_path("3").exists()
    record = json.loads((approve.build_plan_dir() / f"{PLAN_ID}.approval.json").read_text())
    read_requests = [r for _, r in fake.requests if r["action"] == "read"]
    assert [r["read"] for r in read_requests] == ["showbackup", "genid"]
    for request in read_requests:
        assert request["stage"] == "3"
        assert request["token"] == record["tokens"]["build1"]
        assert (request["nbf"], request["exp"]) == (record["nbf"], record["exp"])
        assert request["plan"] == base64.b64encode(plan.canonical_bytes(built_plan)).decode("ascii")


def test_the_stage_approval_refuses_when_a_helper_read_is_refused(
    stored_plan: Path,
    state_dir: Path,
    built_plan: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _dc_run_state(state_dir, built_plan)
    done_2 = int(datetime(2026, 12, 31, 23, 40, tzinfo=timezone.utc).timestamp())
    fake = ReadTransport(
        {
            "showbackup": _read_answer("showbackup", SHOWBACKUP, computer="DC1"),
            "genid": {"ok": False, "status": "refused", "code": "readback_failed", "checks": []},
        },
        completed={"0": done_2 - 600, "1": done_2 - 300, "2": done_2},
    )
    reads = transport.HelperDcReads(fake)
    capsys.readouterr()
    assert _approve_dc_stage(monkeypatch, fake, reads) == 1
    assert not _stage_approval_path("3").exists()
    assert "checkpoint_unverified" in capsys.readouterr().err


def test_the_ad_build_stage_subcommand_gives_the_adapters_the_helper_reads(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = tmp_path / "ad-build.toml"
    path.write_text(
        "version = 1\n[servers.build1]\nhost = \"192.0.2.11\"\nport = 22\n"
        f"key_file = \"{tmp_path}/k\"\nknown_hosts = \"{tmp_path}/kh\"\n",
        encoding="utf-8",
    )
    path.chmod(0o600)
    monkeypatch.setenv("NEWTON_AD_BUILD_CONFIG", str(path))
    seen: list[tuple[Any, Any]] = []

    def fake(plan_id: str, stage: str, *, verifier: Any, transport: Any) -> int:
        seen.append((verifier, transport))
        return 0

    class _Tty(io.StringIO):
        def isatty(self) -> bool:
            return True

    monkeypatch.setattr(approve, "approve_ad_build_stage", fake)
    monkeypatch.setattr("sys.stdin", _Tty(""))
    assert approve.main(["ad-build-stage", PLAN_ID, "3"]) == 0
    (verifier, sent_by), = seen
    assert isinstance(verifier.reads, transport.HelperDcReads)
    assert verifier.reads.transport is sent_by


# ---------------------------------------------------------------------------
# the runner opens the read context before it verifies
# ---------------------------------------------------------------------------


def test_the_runner_opens_the_reads_of_a_server_before_it_verifies_and_closes_them(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from test_build_run import Build  # type: ignore[import-not-found]

    build = Build(monkeypatch)
    events: list[tuple[Any, ...]] = []
    inner = build.adapters

    class Opening:
        def checkpoint(self, server_cfg: Any, kind: str) -> dict[str, str]:
            return inner.checkpoint(server_cfg, kind)

        def verify(self, server_cfg: Any, cp: Any, kind: str, *, stage: str, not_before: int) -> bool:
            events.append(("verify", server_cfg["device"], stage))
            return inner.verify(server_cfg, cp, kind, stage=stage, not_before=not_before)

        def open_reads(self, device: str, **context: Any) -> None:
            events.append(("open", device, context))

        def close_reads(self, device: str) -> None:
            events.append(("close", device))

    build.adapters = Opening()  # type: ignore[assignment]
    state = build.run()
    assert state["state"] == "stopped_for_approval" and state["stage"] == "2", state
    record = json.loads((approve.build_plan_dir() / f"{PLAN_ID}.approval.json").read_text())
    assert events == [
        (
            "open",
            "build1",
            {
                "run": PLAN_ID,
                "plan_bytes": plan.canonical_bytes(build.built),
                "token": record["tokens"]["build1"],
                "nbf": record["nbf"],
                "exp": record["exp"],
                "stage": "2",
            },
        ),
        ("verify", "build1", "2"),
        ("close", "build1"),
    ]
