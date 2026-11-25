"""The checkpoint adapters (PLAN-1.5 task 7, DESIGN-1.5 "Checkpoints",
the maintainer, 2026-11-13).

The verifier of a checkpoint is told the stage it guards and the
earliest time the checkpoint may have been taken at:
``verify(server_cfg, cp, kind, *, stage, not_before)``.  On a server
without a hypervisor the checkpoint is a wbadmin backup, and the stage
decides which backup it must be: before the stages 2 and 7 (a
promotion) the all-critical one, whose ``wbadmin get versions`` lists
"Bare Metal Recovery" in "Can recover"; before the stages 3, 4 and 6 a
backup that lists "System State".  A system-state backup cannot undo a
promotion, so it is refused for the stages 2 and 7.

``not_before`` is the later of the plan approval's NBF and the recorded
completion of the stage before (task 8 passes it, from the journal), so
a checkpoint taken before the previous stage -- stage 2's pre-promotion
one, or one of an earlier run -- never verifies as the DC checkpoint of
a later stage (B1 and M1 of the task 7 triage).
"""

from __future__ import annotations

import copy
import json as _json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from newton_mcp import approve
from newton_mcp.ad.build import checkpoint
from newton_mcp.ad.build import plan
from pwsh_path import PWSH


SYSTEM_STATE = ["System State"]
ALL_CRITICAL = ["Bare Metal Recovery", "System State"]

#: 2026-11-13T06:00:00Z: the plan approval of the 2026-11-13 run in these
#: tests, before m-disk-1 (06:34:38Z) and the workgroup backups (06:38, 06:58).
RUN1_NBF = 1794549600

#: 2026-11-14T07:00:00Z: the plan approval of the 2026-11-14 run in these
#: tests, before m7-wg (07:07:26Z).
RUN2_NBF = 1794639600

#: 2026-11-14T07:17:00Z: stage 2's recorded completion in the 2026-11-14
#: run of these tests: after msDS-GenerationId was stored (07:16:22,
#: MEASURED-1.5 "Checkpoints on BUILD1") and before m7-dc (07:18:09Z).
RUN2_STAGE2_DONE = 1794640620


def test_a_system_state_backup_is_refused_for_the_promotions() -> None:
    for stage in ("2", "7"):
        assert checkpoint.wbadmin_version_verifies(SYSTEM_STATE, stage=stage) is False


def test_a_system_state_backup_verifies_the_dc_stages() -> None:
    for stage in ("3", "4", "6"):
        assert checkpoint.wbadmin_version_verifies(SYSTEM_STATE, stage=stage) is True


def test_an_all_critical_backup_verifies_the_promotions() -> None:
    for stage in ("2", "7"):
        assert checkpoint.wbadmin_version_verifies(ALL_CRITICAL, stage=stage) is True


def test_a_backup_without_system_state_is_refused_for_the_dc_stages() -> None:
    for stage in ("3", "4", "6"):
        assert (
            checkpoint.wbadmin_version_verifies(["Bare Metal Recovery"], stage=stage)
            is False
        )


def test_a_stage_that_takes_no_checkpoint_never_verifies() -> None:
    for stage in ("0", "1", "5", "8", "9", "10", "11", "", " 2"):
        assert checkpoint.wbadmin_version_verifies(ALL_CRITICAL, stage=stage) is False


@pytest.mark.parametrize(
    "items",
    [
        "Bare Metal Recovery",  # a string, not a list of items
        ["bare metal recovery"],  # the words of wbadmin, exactly
        ["Bare Metal Recovery (partial)"],
        [None],
        None,
    ],
)
def test_items_that_are_not_the_words_of_wbadmin_never_verify(items: Any) -> None:
    assert checkpoint.wbadmin_version_verifies(items, stage="2") is False


def test_the_stages_of_the_rule_are_the_stages_that_take_a_checkpoint() -> None:
    taken = {stage for (_, stage) in approve.BUILD_CHECKPOINT_OF_STAGE}
    assert set(checkpoint.WBADMIN_RECOVERY_OF_STAGE) == taken
    assert {
        stage
        for stage, need in checkpoint.WBADMIN_RECOVERY_OF_STAGE.items()
        if need == checkpoint.BARE_METAL
    } == set(approve.BUILD_WBADMIN_ALL_CRITICAL_STAGES)
    for stage in checkpoint.WBADMIN_RECOVERY_OF_STAGE:
        assert plan.STAGE_KINDS[stage] == "irreversible"


# ---------------------------------------------------------------------------
# The adapters (PLAN-1.5 task 7), against the bytes measured on BUILD1.
#
# ``fixtures/checkpoints`` holds the raw answers of the apollo lab: the
# Proxmox API through the scoped token (MEASURED-1.5 "The scoped token",
# "Checkpoints on BUILD1, 2026-11-14"), ``wbadmin get versions`` and
# ``repadmin /showbackup`` on BUILD1.  The msDS-GenerationId reads are the
# ones of stage 2 (``fixtures/stages_0_4``).
# ---------------------------------------------------------------------------


FIXTURES = Path(__file__).resolve().parent / "fixtures" / "checkpoints"
STAGE_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "stages_0_4"

GENID_PRESENT = (STAGE_FIXTURES / "s2-genid-present.txt").read_text(encoding="utf-8")
GENID_ABSENT = (STAGE_FIXTURES / "s2-genid-absent.txt").read_text(encoding="utf-8")


def _fixture(name: str) -> Any:
    return _json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _text(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def _log_lines(name: str) -> list[str]:
    return [entry["t"] for entry in _fixture(name)["data"]]


PVE_SERVER: dict[str, Any] = {
    "device": "build1",
    "role": "dc1",
    "hostname": "BDC1",
    "checkpoint": "proxmox",
    "vmgenid": "590e3ddf-88e7-48eb-a4cf-ba1df5816086",
    "agent": 1,
}


def _pve_target(tmp_path: Path, secret: str = "00000000-1111-2222-3333-444444444444") -> Any:
    token = tmp_path / "pve-token"
    token.write_text(secret + "\n", encoding="utf-8")
    ca = tmp_path / "pve-root-ca.pem"
    ca.write_text("synthetic\n", encoding="utf-8")
    return checkpoint.ProxmoxTarget(
        api="https://pve.example.test:8006/api2/json",
        node="Apollo",
        vmid="731",
        token_id="newton-build@pve!checkpoint",
        token_file=token,
        ca_file=ca,
    )


class FakePve:
    """The Proxmox API of the lab, answering with measured bytes.

    Each answer is keyed on the method and the path; the calls are
    recorded with their parameters.
    """

    def __init__(self, answers: dict[tuple[str, str], Any]) -> None:
        self.answers = answers
        self.calls: list[tuple[str, str, dict[str, str]]] = []

    def __call__(
        self, target: Any, method: str, path: str, params: Any = None
    ) -> Any:
        self.calls.append((method, path, dict(params or {})))
        key = (method, path)
        if key not in self.answers:
            raise OSError(f"no answer for {method} {path}")
        return copy.deepcopy(self.answers[key])


def _pve_answers(case: str, *, upid: str | None = None) -> dict[tuple[str, str], Any]:
    post = _fixture(f"pve-{case}-post.json")
    the_upid = upid or post["data"]
    from urllib.parse import quote

    task = "/nodes/Apollo/tasks/" + quote(the_upid, safe="")
    return {
        ("POST", "/nodes/Apollo/qemu/731/snapshot"): post,
        ("GET", task + "/status"): _fixture(f"pve-{case}-status.json"),
        ("GET", task + "/log"): _fixture(f"pve-{case}-log.json"),
        ("GET", "/nodes/Apollo/qemu/731/snapshot"): _fixture(f"pve-{case}-snapshots.json"),
    }


#: The snapshot each measured case took (MEASURED-1.5).
PVE_SNAPNAMES = {
    "agent": "m-disk-1",
    "noagent": "m-nofreeze",
    "wg": "m7-wg",
    "dcagent": "m7-dc",
    "dcnoagent": "m7-dc-noagent",
    "dcnovss": "m7-dc-novss",
    "dcnoprov": "m7-dc-noprov",
}


def _pve_cp(case: str) -> dict[str, str]:
    return {"name": PVE_SNAPNAMES[case], "id": _fixture(f"pve-{case}-post.json")["data"]}


def _pve_adapter(
    tmp_path: Path, fake: FakePve, genid: str = GENID_PRESENT
) -> Any:
    return checkpoint.ProxmoxAdapter(
        {"build1": _pve_target(tmp_path)},
        request=fake,
        read_genid=lambda server_cfg: genid,
        sleep=lambda s: None,
    )


# -- the Proxmox task log rule ------------------------------------------------


def test_the_measured_freeze_and_thaw_log_verifies() -> None:
    for case in ("agent", "dcagent", "wg"):
        lines = _log_lines(f"pve-{case}-log.json")
        snap = _pve_cp(case)["name"]
        assert checkpoint.proxmox_log_verifies(lines, vmid="731", snapname=snap) is True


def test_a_log_that_skipped_the_freeze_is_refused() -> None:
    for case in ("noagent", "dcnoagent"):
        lines = _log_lines(f"pve-{case}-log.json")
        assert lines[0].startswith("skipping guest filesystem freeze")
        snap = _pve_cp(case)["name"]
        assert checkpoint.proxmox_log_verifies(lines, vmid="731", snapname=snap) is False


def test_a_stopped_vm_log_has_no_freeze_and_is_refused() -> None:
    lines = _log_lines("pve-stopped-log.json")
    assert not any("freeze" in line for line in lines)
    assert (
        checkpoint.proxmox_log_verifies(lines, vmid="731", snapname="fresh-2026-11-13")
        is False
    )


def test_a_failed_freeze_log_is_refused() -> None:
    """Measured: with VSS disabled, or the agent's VSS provider, the
    freeze fails and the task still ends exitstatus OK and TASK OK, with
    the freeze and the thaw lines; the failure is one line between."""
    for case in ("dcnovss", "dcnoprov"):
        lines = _log_lines(f"pve-{case}-log.json")
        assert lines[0] == "freeze guest filesystem" and lines[-2:] == ["thaw guest filesystem", "TASK OK"]
        assert lines[1].startswith("unable to freeze guest fs - ")
        assert _fixture(f"pve-{case}-status.json")["data"]["exitstatus"] == "OK"
        snap = _pve_cp(case)["name"]
        assert checkpoint.proxmox_log_verifies(lines, vmid="731", snapname=snap) is False


@pytest.mark.parametrize(
    "extra",
    [
        "guest-fsfreeze-freeze problems - VSS error",
        "unable to freeze guest fs - failed to initialize for backup: Windows error 0x80042302: ",
        "  WARNING: something else entirely",
        "  WARNING: You have not turned on protection against thin pools running out of space. ",
        "freeze guest filesystem",
        "thaw guest filesystem",
        "  Logical volume \"snap_vm-732-disk-0_m-disk-1\" created.",
        "  Logical volume \"snap_vm-731-disk-0_other\" created.",
        "snapshotting 'drive-sata0' (vmdata:vm-732-disk-0)",
        "",
    ],
)
def test_any_other_line_between_freeze_and_thaw_is_refused(extra: str) -> None:
    lines = _log_lines("pve-agent-log.json")
    thaw = lines.index("thaw guest filesystem")
    assert checkpoint.proxmox_log_verifies(lines, vmid="731", snapname="m-disk-1") is True
    changed = lines[:thaw] + [extra] + lines[thaw:]
    assert checkpoint.proxmox_log_verifies(changed, vmid="731", snapname="m-disk-1") is False


def test_the_freeze_the_thaw_and_task_ok_must_be_in_order() -> None:
    lines = _log_lines("pve-agent-log.json")
    ok = dict(vmid="731", snapname="m-disk-1")
    freeze, thaw = lines[0], lines[-2]
    assert checkpoint.proxmox_log_verifies(lines, **ok) is True
    swapped = [thaw] + lines[1:-2] + [freeze] + lines[-1:]
    assert checkpoint.proxmox_log_verifies(swapped, **ok) is False
    assert checkpoint.proxmox_log_verifies(lines[1:], **ok) is False  # no freeze
    assert checkpoint.proxmox_log_verifies(lines[:-2] + lines[-1:], **ok) is False  # no thaw
    assert checkpoint.proxmox_log_verifies(lines[:-1], **ok) is False  # no TASK OK
    assert checkpoint.proxmox_log_verifies(lines + ["TASK OK"], **ok) is False
    assert checkpoint.proxmox_log_verifies(["note"] + lines, **ok) is False
    warned = lines[:-1] + ["TASK WARNINGS: 1"]
    assert checkpoint.proxmox_log_verifies(warned, **ok) is False


def test_a_disk_without_its_snapshot_volume_is_refused() -> None:
    lines = _log_lines("pve-agent-log.json")
    ok = dict(vmid="731", snapname="m-disk-1")
    created = [i for i, line in enumerate(lines) if "Logical volume" in line]
    assert len(created) == 1
    dropped = lines[: created[0]] + lines[created[0] + 1 :]
    assert checkpoint.proxmox_log_verifies(dropped, **ok) is False
    other_disk = list(lines)
    other_disk[created[0]] = '  Logical volume "snap_vm-731-disk-1_m-disk-1" created.'
    assert checkpoint.proxmox_log_verifies(other_disk, **ok) is False
    assert checkpoint.proxmox_log_verifies(["freeze guest filesystem", "thaw guest filesystem", "TASK OK"], **ok) is False


def test_the_log_rule_takes_only_lists_of_strings() -> None:
    for lines in (None, "freeze guest filesystem", [None], [1, 2]):
        assert checkpoint.proxmox_log_verifies(lines, vmid="731", snapname="m-disk-1") is False  # type: ignore[arg-type]


# -- the Proxmox adapter ----------------------------------------------------------


def test_the_proxmox_checkpoint_posts_a_vmstate_0_snapshot(tmp_path: Path) -> None:
    fake = FakePve(_pve_answers("agent"))
    adapter = _pve_adapter(tmp_path, fake)
    cp = adapter.checkpoint(PVE_SERVER, "dc")
    assert set(cp) == {"name", "id"}
    assert cp["id"] == _fixture("pve-agent-post.json")["data"]
    assert plan.CHECKPOINT_ID_RE.fullmatch(cp["id"])
    method, path, params = fake.calls[0]
    assert (method, path) == ("POST", "/nodes/Apollo/qemu/731/snapshot")
    assert params["vmstate"] == "0"
    assert params["snapname"] == cp["name"]
    assert checkpoint.PROXMOX_SNAPNAME_RE.fullmatch(cp["name"])
    # it waits for the task to stop
    assert any(c[1].endswith("/status") for c in fake.calls)


def test_the_proxmox_checkpoint_verifies_against_the_measured_bytes(tmp_path: Path) -> None:
    for case, kind, stage, bound in (
        ("agent", "workgroup", "2", RUN1_NBF),
        ("wg", "workgroup", "2", RUN2_NBF),
        ("dcagent", "dc", "3", RUN2_STAGE2_DONE),
        ("dcagent", "dc", "7", RUN2_STAGE2_DONE),
    ):
        fake = FakePve(_pve_answers(case))
        adapter = _pve_adapter(tmp_path, fake)
        assert adapter.verify(PVE_SERVER, _pve_cp(case), kind, stage=stage, not_before=bound) is True


def test_a_proxmox_snapshot_without_the_freeze_is_unverified(tmp_path: Path) -> None:
    for case, kind, stage in (
        ("noagent", "workgroup", "2"),
        ("dcnoagent", "dc", "3"),
        ("dcnovss", "dc", "4"),
        ("dcnoprov", "dc", "6"),
    ):
        adapter = _pve_adapter(tmp_path, FakePve(_pve_answers(case)))
        assert adapter.verify(PVE_SERVER, _pve_cp(case), kind, stage=stage, not_before=RUN1_NBF) is False


def test_a_proxmox_task_whose_exitstatus_is_not_ok_is_unverified(tmp_path: Path) -> None:
    for exitstatus in ("WARNINGS: 1", "ERROR", "", None):
        answers = _pve_answers("dcagent")
        key = [k for k in answers if k[1].endswith("/status")][0]
        answers[key]["data"]["exitstatus"] = exitstatus
        adapter = _pve_adapter(tmp_path, FakePve(answers))
        assert adapter.verify(PVE_SERVER, _pve_cp("dcagent"), "dc", stage="3", not_before=RUN2_STAGE2_DONE) is False


def test_a_proxmox_task_still_running_or_of_another_vm_is_unverified(tmp_path: Path) -> None:
    for field, value in (("status", "running"), ("id", "732"), ("type", "qmrollback"), ("upid", "UPID:x")):
        answers = _pve_answers("dcagent")
        key = [k for k in answers if k[1].endswith("/status")][0]
        answers[key]["data"][field] = value
        adapter = _pve_adapter(tmp_path, FakePve(answers))
        assert adapter.verify(PVE_SERVER, _pve_cp("dcagent"), "dc", stage="3", not_before=RUN2_STAGE2_DONE) is False


def test_a_truncated_proxmox_log_is_unverified(tmp_path: Path) -> None:
    answers = _pve_answers("dcagent")
    key = [k for k in answers if k[1].endswith("/log")][0]
    answers[key]["total"] = answers[key]["total"] + 1
    adapter = _pve_adapter(tmp_path, FakePve(answers))
    assert adapter.verify(PVE_SERVER, _pve_cp("dcagent"), "dc", stage="3", not_before=RUN2_STAGE2_DONE) is False
    answers = _pve_answers("dcagent")
    del answers[key]["total"]
    adapter = _pve_adapter(tmp_path, FakePve(answers))
    assert adapter.verify(PVE_SERVER, _pve_cp("dcagent"), "dc", stage="3", not_before=RUN2_STAGE2_DONE) is False


def test_a_proxmox_snapshot_that_is_not_listed_or_holds_ram_is_unverified(tmp_path: Path) -> None:
    cp = _pve_cp("dcagent")
    answers = _pve_answers("dcagent")
    key = ("GET", "/nodes/Apollo/qemu/731/snapshot")
    answers[key]["data"] = [s for s in answers[key]["data"] if s["name"] != cp["name"]]
    assert _pve_adapter(tmp_path, FakePve(answers)).verify(PVE_SERVER, cp, "dc", stage="3", not_before=RUN2_STAGE2_DONE) is False
    answers = _pve_answers("dcagent")
    for s in answers[key]["data"]:
        if s["name"] == cp["name"]:
            s["vmstate"] = 1
    assert _pve_adapter(tmp_path, FakePve(answers)).verify(PVE_SERVER, cp, "dc", stage="3", not_before=RUN2_STAGE2_DONE) is False


def test_a_proxmox_checkpoint_of_another_task_is_unverified(tmp_path: Path) -> None:
    cp = _pve_cp("dcagent")
    other = dict(cp, id=cp["id"].replace(":731:", ":732:"))
    answers = _pve_answers("dcagent", upid=other["id"])
    assert _pve_adapter(tmp_path, FakePve(answers)).verify(PVE_SERVER, other, "dc", stage="3", not_before=RUN2_STAGE2_DONE) is False
    other = dict(cp, id=cp["id"].replace("qmsnapshot", "qmrollback"))
    answers = _pve_answers("dcagent", upid=other["id"])
    assert _pve_adapter(tmp_path, FakePve(answers)).verify(PVE_SERVER, other, "dc", stage="3", not_before=RUN2_STAGE2_DONE) is False
    renamed = dict(cp, name="m7-other")
    assert _pve_adapter(tmp_path, FakePve(_pve_answers("dcagent"))).verify(PVE_SERVER, renamed, "dc", stage="3", not_before=RUN2_STAGE2_DONE) is False


def test_a_dc_checkpoint_without_the_generation_id_is_unverified(tmp_path: Path) -> None:
    cp = _pve_cp("dcagent")
    for genid in (GENID_ABSENT, "", "msDS-GenerationId on CN=OTHER,OU=Domain Controllers,DC=build,DC=newton,DC=test: present, 8 bytes, dfff81575195ab49\n"):
        adapter = _pve_adapter(tmp_path, FakePve(_pve_answers("dcagent")), genid=genid)
        assert adapter.verify(PVE_SERVER, cp, "dc", stage="3", not_before=RUN2_STAGE2_DONE) is False
    # a workgroup checkpoint has no directory to read
    reads: list[Any] = []
    adapter = checkpoint.ProxmoxAdapter(
        {"build1": _pve_target(tmp_path)},
        request=FakePve(_pve_answers("agent")),
        read_genid=lambda s: reads.append(s) or GENID_ABSENT,
        sleep=lambda s: None,
    )
    assert adapter.verify(PVE_SERVER, _pve_cp("agent"), "workgroup", stage="2", not_before=RUN1_NBF) is True
    assert reads == []


def test_the_proxmox_adapter_refuses_a_kind_the_stage_does_not_take(tmp_path: Path) -> None:
    adapter = _pve_adapter(tmp_path, FakePve(_pve_answers("dcagent")))
    cp = _pve_cp("dcagent")
    assert adapter.verify(PVE_SERVER, cp, "workgroup", stage="3", not_before=RUN2_STAGE2_DONE) is False
    assert adapter.verify(PVE_SERVER, cp, "dc", stage="2", not_before=RUN2_STAGE2_DONE) is False
    assert adapter.verify(PVE_SERVER, cp, "dc", stage="5", not_before=RUN2_STAGE2_DONE) is False
    assert adapter.verify(dict(PVE_SERVER, checkpoint="hyperv"), cp, "dc", stage="3", not_before=RUN2_STAGE2_DONE) is False
    assert adapter.verify(dict(PVE_SERVER, device="build9"), cp, "dc", stage="3", not_before=RUN2_STAGE2_DONE) is False


def test_the_proxmox_adapter_needs_the_stage_by_keyword(tmp_path: Path) -> None:
    adapter = _pve_adapter(tmp_path, FakePve(_pve_answers("dcagent")))
    with pytest.raises(TypeError):
        adapter.verify(PVE_SERVER, _pve_cp("dcagent"), "dc", "3", not_before=RUN2_STAGE2_DONE)  # type: ignore[misc]


class _Opened:
    def __init__(self, body: bytes) -> None:
        self.body = body

    def read(self) -> bytes:
        return self.body

    def __enter__(self) -> "_Opened":
        return self

    def __exit__(self, *exc: object) -> None:
        return None


class FakeOpener:
    def __init__(self, body: Any) -> None:
        self.body = _json.dumps(body).encode("utf-8")
        self.requests: list[Any] = []

    def open(self, request: Any, timeout: float | None = None) -> _Opened:
        self.requests.append(request)
        return _Opened(self.body)


def test_the_token_reaches_the_request_only_from_its_file(tmp_path: Path) -> None:
    secret = "5ec2e7a1-0000-4000-8000-00000000beef"
    target = _pve_target(tmp_path, secret=secret)
    assert secret not in repr(target)
    opener = FakeOpener(_fixture("pve-agent-post.json"))
    body = checkpoint.pve_request(
        target,
        "POST",
        "/nodes/Apollo/qemu/731/snapshot",
        {"snapname": "m7-x", "vmstate": "0"},
        opener=opener,
    )
    assert body == _fixture("pve-agent-post.json")
    (request,) = opener.requests
    assert request.get_header("Authorization") == (
        "PVEAPIToken=newton-build@pve!checkpoint=" + secret
    )
    assert secret not in request.full_url
    assert secret not in (request.data or b"").decode("utf-8")
    assert request.full_url == "https://pve.example.test:8006/api2/json/nodes/Apollo/qemu/731/snapshot"
    assert request.get_method() == "POST"
    # the secret is read at the call: a new file is a new secret
    target.token_file.write_text("second-secret\n", encoding="utf-8")
    checkpoint.pve_request(target, "GET", "/nodes/Apollo/qemu/731/snapshot", opener=opener)
    assert opener.requests[-1].get_header("Authorization").endswith("=second-secret")


def test_the_token_file_must_hold_one_secret(tmp_path: Path) -> None:
    target = _pve_target(tmp_path)
    opener = FakeOpener({})
    for content in ("", "\n", "x7q1 z9w2\n", "x7q1\nz9w2\n", "x7q1;z9w2\n"):
        target.token_file.write_text(content, encoding="utf-8")
        with pytest.raises(ValueError) as caught:
            checkpoint.pve_request(target, "GET", "/version", opener=opener)
        assert "x7q1" not in str(caught.value) and "z9w2" not in str(caught.value)
    assert opener.requests == []


def test_a_proxmox_target_outside_its_grammar_is_refused(tmp_path: Path) -> None:
    good = _pve_target(tmp_path)
    fields = dict(
        api=good.api, node=good.node, vmid=good.vmid, token_id=good.token_id,
        token_file=good.token_file, ca_file=good.ca_file,
    )
    for field, value in (
        ("api", "http://pve.example.test:8006/api2/json"),
        ("node", "Apollo/../x"),
        ("vmid", "731 "),
        ("vmid", "abc"),
        ("token_id", "newton-build@pve"),
    ):
        with pytest.raises(ValueError):
            checkpoint.ProxmoxTarget(**dict(fields, **{field: value}))


# -- the wbadmin read ---------------------------------------------------------------

WB_SERVER: dict[str, Any] = {"device": "build1", "role": "dc1", "hostname": "BDC1", "checkpoint": "wbadmin"}

#: The wbadmin DC backups of BUILD1 (2026-11-14): system state 07:19,
#: all-critical 07:32, both after RUN2_STAGE2_DONE.
WB_DC_SS = {"name": "wbadmin-build1-dc", "id": "11/14/2026-07:19"}
WB_DC_AC = {"name": "wbadmin-build1-dc", "id": "11/14/2026-07:32"}


def test_wbadmin_get_versions_is_parsed_as_measured() -> None:
    versions = checkpoint.parse_wbadmin_versions(_text("wbadmin-versions-workgroup-ac.txt"))
    assert [v.identifier for v in versions] == ["11/13/2026-06:38", "11/13/2026-06:58"]
    assert versions[0].can_recover == ("Volume(s)", "File(s)", "Application(s)", "System State")
    assert versions[1].can_recover == (
        "Volume(s)", "File(s)", "Application(s)", "Bare Metal Recovery", "System State",
    )
    assert versions[1].time == datetime(2026, 11, 13, 6, 58, tzinfo=timezone.utc)
    # the "Backup time" line is the DC's local 12-hour time, kept naive
    assert versions[1].backup_time == datetime(2026, 11, 13, 6, 58)
    assert versions[0].backup_time == datetime(2026, 11, 13, 6, 38)
    (only,) = checkpoint.parse_wbadmin_versions(_text("wbadmin-versions-workgroup-ss.txt"))
    assert only.identifier == "11/13/2026-06:38"


@pytest.mark.parametrize(
    "mangle",
    [
        lambda t: t.replace("Version identifier: 11/13/2026-06:58", "Version identifier: 11/13/2026 06:58"),
        lambda t: t.replace("Can recover: ", "Can recover:"),
        lambda t: t.replace("Snapshot ID: {8033a50b-0e6d-415f-b71b-5916d8d50079}\n", ""),
        lambda t: t.replace("wbadmin 1.0 - Backup command-line tool", "something else"),
        lambda t: t + "Backup time: 11/13/2026 7:00 AM \n",
        lambda t: t.replace("Version identifier: 11/13/2026-06:58", "Version identifier: 11/13/2026-06:38"),
    ],
)
def test_a_wbadmin_answer_outside_the_measured_shape_is_refused(mangle: Any) -> None:
    text = _text("wbadmin-versions-workgroup-ac.txt")
    checkpoint.parse_wbadmin_versions(text)
    with pytest.raises(ValueError):
        checkpoint.parse_wbadmin_versions(mangle(text))


def _wb_adapter(
    text: str,
    *,
    computer: str = "BDC1",
    genid: str = GENID_PRESENT,
    reads: list[Any] | None = None,
    offset: Any = 0,
) -> Any:
    """``offset`` is the DC's UTC offset the read reports: 0 for BUILD1,
    whose guest runs UTC (MEASURED-1.5 "Checkpoints on BUILD1")."""

    def read_versions(server_cfg: Any) -> Any:
        if reads is not None:
            reads.append(dict(server_cfg))
        return checkpoint.WbadminRead(computer=computer, text=text, utc_offset_minutes=offset)

    return checkpoint.WbadminAdapter(
        read_versions=read_versions,
        read_genid=lambda server_cfg: genid,
        take=lambda server_cfg, backup: "11/13/2026-06:58",
    )


def test_the_wbadmin_read_takes_the_stage_rule() -> None:
    """The DC backups of BUILD1 serve the DC stages by the stage rule; the
    workgroup backups serve stage 2 only (M1 of the task 7 triage: a
    workgroup server's version is never a DC checkpoint)."""
    dc = _wb_adapter(_text("wbadmin-versions-dc-ac.txt"))
    for stage in ("3", "4", "6"):
        assert dc.verify(WB_SERVER, WB_DC_SS, "dc", stage=stage, not_before=RUN2_STAGE2_DONE) is True
        assert dc.verify(WB_SERVER, WB_DC_AC, "dc", stage=stage, not_before=RUN2_STAGE2_DONE) is True
    assert dc.verify(WB_SERVER, WB_DC_SS, "dc", stage="7", not_before=RUN2_STAGE2_DONE) is False
    assert dc.verify(WB_SERVER, WB_DC_AC, "dc", stage="7", not_before=RUN2_STAGE2_DONE) is True
    wg = _wb_adapter(_text("wbadmin-versions-workgroup-ac.txt"))
    ss = {"name": "wbadmin-build1", "id": "11/13/2026-06:38"}
    ac = {"name": "wbadmin-build1", "id": "11/13/2026-06:58"}
    assert wg.verify(WB_SERVER, ss, "workgroup", stage="2", not_before=RUN1_NBF) is False
    assert wg.verify(WB_SERVER, ac, "workgroup", stage="2", not_before=RUN1_NBF) is True
    # the workgroup server's versions, with the genid of the DC it became,
    # are older than the completion of stage 2: never a DC checkpoint
    stage2_done = int(datetime(2026, 11, 13, 7, 10, tzinfo=timezone.utc).timestamp())
    for cp in (ss, ac):
        for stage in ("3", "4", "6", "7"):
            assert wg.verify(WB_SERVER, cp, "dc", stage=stage, not_before=stage2_done) is False


def test_the_wbadmin_read_picks_the_version_of_the_checkpoint() -> None:
    adapter = _wb_adapter(_text("wbadmin-versions-dc-ss.txt"))
    assert adapter.verify(WB_SERVER, WB_DC_AC, "dc", stage="3", not_before=RUN2_STAGE2_DONE) is False


def test_a_wbadmin_version_older_than_the_bound_is_refused() -> None:
    """The version identifier is the minute the backup started: the bound
    is floored to its minute, never further."""
    text = _text("wbadmin-versions-dc-ac.txt")
    at = int(datetime(2026, 11, 14, 7, 32, tzinfo=timezone.utc).timestamp())
    adapter = _wb_adapter(text)
    assert adapter.verify(WB_SERVER, WB_DC_AC, "dc", stage="7", not_before=at) is True
    assert adapter.verify(WB_SERVER, WB_DC_AC, "dc", stage="7", not_before=at + 59) is True
    assert adapter.verify(WB_SERVER, WB_DC_AC, "dc", stage="7", not_before=at + 60) is False
    assert adapter.verify(WB_SERVER, WB_DC_AC, "dc", stage="7", not_before=at + 3600) is False
    assert adapter.verify(WB_SERVER, WB_DC_AC, "workgroup", stage="2", not_before=at + 60) is False


def test_a_wbadmin_verify_needs_the_bound() -> None:
    """No default and no way to omit the bound (B1/M1 of the triage)."""
    adapter = _wb_adapter(_text("wbadmin-versions-dc-ac.txt"))
    for kind, stage in (("dc", "3"), ("dc", "7"), ("workgroup", "2")):
        with pytest.raises(TypeError):
            adapter.verify(WB_SERVER, WB_DC_AC, kind, stage=stage)
        for bad in (None, True, "1794640620", 1794640620.0):
            with pytest.raises(TypeError):
                adapter.verify(WB_SERVER, WB_DC_AC, kind, stage=stage, not_before=bad)
    with pytest.raises(TypeError):
        checkpoint.WbadminAdapter(  # type: ignore[call-arg]
            read_versions=lambda s: checkpoint.WbadminRead(computer="BDC1", text="", utc_offset_minutes=0),
            read_genid=lambda s: GENID_PRESENT,
            take=lambda s, b: "11/14/2026-07:58",
            not_before=RUN2_NBF,
        )


def test_the_wbadmin_adapter_receives_the_stage_by_keyword() -> None:
    reads: list[Any] = []
    adapter = _wb_adapter(_text("wbadmin-versions-dc-ac.txt"), reads=reads)
    with pytest.raises(TypeError):
        adapter.verify(WB_SERVER, WB_DC_AC, "dc", not_before=RUN2_STAGE2_DONE)  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        adapter.verify(WB_SERVER, WB_DC_AC, "dc", "7", not_before=RUN2_STAGE2_DONE)  # type: ignore[misc]
    assert adapter.verify(WB_SERVER, WB_DC_SS, "dc", stage="7", not_before=RUN2_STAGE2_DONE) is False
    assert adapter.verify(WB_SERVER, WB_DC_SS, "dc", stage="3", not_before=RUN2_STAGE2_DONE) is True
    assert reads == [WB_SERVER, WB_SERVER]


def test_the_wbadmin_adapter_refuses_a_server_with_a_hypervisor_or_another_kind() -> None:
    reads: list[Any] = []
    adapter = _wb_adapter(_text("wbadmin-versions-dc-ac.txt"), reads=reads)
    for method in ("hyperv", "proxmox", "", None):
        server = dict(WB_SERVER, checkpoint=method)
        assert adapter.verify(server, WB_DC_AC, "dc", stage="7", not_before=RUN2_STAGE2_DONE) is False
    assert adapter.verify(WB_SERVER, WB_DC_AC, "vm", stage="7", not_before=RUN2_STAGE2_DONE) is False
    assert reads == []


def test_a_wbadmin_read_that_fails_raises() -> None:
    def read(server_cfg: Any) -> Any:
        raise OSError("wbadmin did not answer")

    adapter = checkpoint.WbadminAdapter(
        read_versions=read, read_genid=lambda s: GENID_PRESENT, take=lambda s, b: "x"
    )
    with pytest.raises(OSError):
        adapter.verify(WB_SERVER, WB_DC_AC, "dc", stage="7", not_before=RUN2_STAGE2_DONE)
    with pytest.raises(checkpoint.CheckpointUnverified):
        checkpoint.require_verified(
            adapter, WB_SERVER, WB_DC_AC, "dc", stage="7", not_before=RUN2_STAGE2_DONE
        )


def test_wbadmin_verifier_is_not_in_the_product() -> None:
    """The old WbadminVerifier had no genid read, no bound and no
    computer check: nothing in newton_mcp may hold it (m2 of the triage)."""
    assert not hasattr(checkpoint, "WbadminVerifier")
    package = Path(checkpoint.__file__).resolve().parents[2]
    assert package.name == "newton_mcp"
    holders = [
        str(path)
        for path in package.rglob("*")
        if path.is_file() and path.suffix in (".py", ".ps1", ".toml", ".json") and "WbadminVerifier" in path.read_text(encoding="utf-8", errors="replace")
    ]
    assert holders == []


def test_a_wbadmin_version_of_another_server_is_refused() -> None:
    text = _text("wbadmin-versions-dc-ac.txt")
    ok = dict(stage="7", not_before=RUN2_STAGE2_DONE)
    assert _wb_adapter(text, computer="bdc1").verify(WB_SERVER, WB_DC_AC, "dc", **ok) is True
    for other in ("BDC2", "", "BDC1 ", "BDC10"):
        assert _wb_adapter(text, computer=other).verify(WB_SERVER, WB_DC_AC, "dc", **ok) is False


def test_a_wbadmin_dc_checkpoint_without_the_generation_id_is_unverified() -> None:
    dc = _wb_adapter(_text("wbadmin-versions-dc-ac.txt"), genid=GENID_ABSENT)
    assert dc.verify(WB_SERVER, WB_DC_AC, "dc", stage="3", not_before=RUN2_STAGE2_DONE) is False
    wg = _wb_adapter(_text("wbadmin-versions-workgroup-ac.txt"), genid=GENID_ABSENT)
    ac = {"name": "wbadmin-build1", "id": "11/13/2026-06:58"}
    assert wg.verify(WB_SERVER, ac, "workgroup", stage="2", not_before=RUN1_NBF) is True


def test_a_wbadmin_answer_outside_its_shape_is_unverified() -> None:
    assert _wb_adapter("garbage").verify(WB_SERVER, WB_DC_AC, "dc", stage="3", not_before=RUN2_STAGE2_DONE) is False


# -- the wbadmin clocks (W1 of the ccdd15e review) -------------------------------
#
# The "Version identifier" is read as a UTC minute; the "Backup time" line
# is the DC's local time.  A version verifies only when its identifier is
# its Backup time minus the DC's UTC offset (the read carries it), so an
# identifier in local time on a DC east of UTC is never read as a later
# UTC minute.

#: The measured all-critical version of BUILD1 (2026-11-14 07:32 UTC).
WB_AC_TIME = "Backup time: 11/14/2026 7:32 AM "
WB_AC_ID = "Version identifier: 11/14/2026-07:32"


def _wb_clock(backup_time: str, identifier: str) -> str:
    """The measured DC answer with its all-critical version's Backup time
    (``M/D/YYYY H:MM AM``) and identifier (``MM/DD/YYYY-HH:MM``) set."""
    text = _text("wbadmin-versions-dc-ac.txt")
    assert text.count(WB_AC_TIME) == 1 and text.count(WB_AC_ID) == 1
    return text.replace(WB_AC_TIME, f"Backup time: {backup_time} ").replace(
        WB_AC_ID, f"Version identifier: {identifier}"
    )


def _utc(*parts: int) -> int:
    return int(datetime(*parts, tzinfo=timezone.utc).timestamp())


def _wb_clock_verifies(backup_time: str, identifier: str, offset: Any, not_before: int) -> bool:
    adapter = _wb_adapter(_wb_clock(backup_time, identifier), offset=offset)
    cp = {"name": "wbadmin-build1-dc", "id": identifier}
    return adapter.verify(WB_SERVER, cp, "dc", stage="7", not_before=not_before)


def test_the_wbadmin_read_carries_the_dc_utc_offset() -> None:
    assert checkpoint.WbadminRead._fields == ("computer", "text", "utc_offset_minutes")
    with pytest.raises(TypeError):
        checkpoint.WbadminRead(computer="BDC1", text="")  # type: ignore[call-arg]


def test_the_measured_wbadmin_clocks_at_offset_0_verify() -> None:
    text = _text("wbadmin-versions-dc-ac.txt")
    at = _utc(2026, 11, 14, 7, 32)
    assert _wb_adapter(text, offset=0).verify(WB_SERVER, WB_DC_AC, "dc", stage="7", not_before=at) is True
    assert _wb_adapter(text, offset=0).verify(WB_SERVER, WB_DC_AC, "dc", stage="7", not_before=at + 60) is False


def test_a_local_version_identifier_east_of_utc_is_refused() -> None:
    """The fail-open case: on a DC at UTC+2 an identifier in local time
    (09:32) read as UTC is two hours later than the backup (07:32 UTC),
    and would meet a bound of 08:00 the backup does not."""
    for bound in (_utc(2026, 11, 14, 7, 0), _utc(2026, 11, 14, 8, 0), _utc(2026, 11, 14, 9, 32)):
        assert _wb_clock_verifies("11/14/2026 9:32 AM", "11/14/2026-09:32", 120, bound) is False


def test_a_utc_version_identifier_east_of_utc_meets_its_bound() -> None:
    assert _wb_clock_verifies("11/14/2026 9:32 AM", "11/14/2026-07:32", 120, _utc(2026, 11, 14, 7, 32)) is True
    assert _wb_clock_verifies("11/14/2026 9:32 AM", "11/14/2026-07:32", 120, _utc(2026, 11, 14, 7, 32, 59)) is True
    assert _wb_clock_verifies("11/14/2026 9:32 AM", "11/14/2026-07:32", 120, _utc(2026, 11, 14, 7, 33)) is False
    assert _wb_clock_verifies("11/14/2026 9:32 AM", "11/14/2026-07:32", 120, _utc(2026, 11, 14, 9, 0)) is False


def test_a_version_identifier_west_of_utc_meets_its_bound() -> None:
    # UTC-5: local 2:32 AM is 07:32 UTC
    assert _wb_clock_verifies("11/14/2026 2:32 AM", "11/14/2026-07:32", -300, _utc(2026, 11, 14, 7, 32)) is True
    assert _wb_clock_verifies("11/14/2026 2:32 AM", "11/14/2026-07:32", -300, _utc(2026, 11, 14, 7, 33)) is False
    # an identifier in local time west of UTC reads earlier: refused too
    assert _wb_clock_verifies("11/14/2026 2:32 AM", "11/14/2026-02:32", -300, _utc(2026, 11, 14, 2, 0)) is False
    # local 11:32 PM the day before is 04:32 UTC
    assert _wb_clock_verifies("11/13/2026 11:32 PM", "11/14/2026-04:32", -300, _utc(2026, 11, 14, 4, 32)) is True
    assert _wb_clock_verifies("11/13/2026 11:32 PM", "11/14/2026-04:32", -300, _utc(2026, 11, 14, 4, 33)) is False
    assert _wb_clock_verifies("11/13/2026 11:32 PM", "11/13/2026-04:32", -300, _utc(2026, 11, 13, 4, 0)) is False


def test_the_backup_time_is_read_on_the_12_hour_clock() -> None:
    at = _utc(2026, 11, 14, 0, 0)
    # UTC+5:30: local 1:02 PM is 07:32 UTC
    assert _wb_clock_verifies("11/14/2026 1:02 PM", "11/14/2026-07:32", 330, at) is True
    assert _wb_clock_verifies("11/14/2026 1:02 AM", "11/14/2026-07:32", 330, at) is False
    # 12 AM is midnight, 12 PM is noon
    assert _wb_clock_verifies("11/14/2026 12:32 AM", "11/14/2026-00:32", 0, at) is True
    assert _wb_clock_verifies("11/14/2026 12:32 AM", "11/14/2026-12:32", 0, at) is False
    assert _wb_clock_verifies("11/14/2026 12:32 PM", "11/14/2026-12:32", 0, at) is True
    assert _wb_clock_verifies("11/14/2026 12:32 PM", "11/14/2026-00:32", 0, at) is False


def test_a_backup_time_a_minute_off_its_identifier_is_refused() -> None:
    at = _utc(2026, 11, 14, 7, 0)
    assert _wb_clock_verifies("11/14/2026 7:33 AM", "11/14/2026-07:32", 0, at) is False
    assert _wb_clock_verifies("11/14/2026 7:31 AM", "11/14/2026-07:32", 0, at) is False
    assert _wb_clock_verifies("11/14/2026 9:32 AM", "11/14/2026-07:32", 119, at) is False
    assert _wb_clock_verifies("11/15/2026 7:32 AM", "11/14/2026-07:32", 0, at) is False


@pytest.mark.parametrize(
    ("backup_time", "offset"),
    [
        ("11/14/2026 7:32 AM", False),  # a bool, though False == 0
        ("11/14/2026 8:32 AM", True),  # a bool, though True == 1 would not match anyway
        ("11/14/2026 7:32 AM", "0"),
        ("11/14/2026 7:32 AM", 0.0),
        ("11/14/2026 7:32 AM", None),
        ("11/15/2026 7:32 AM", 1440),  # it would match: the range refuses it
        ("11/13/2026 7:32 AM", -1440),
        ("11/15/2026 8:32 AM", 1500),
    ],
)
def test_a_wbadmin_read_with_a_bad_offset_is_unverified(backup_time: str, offset: Any) -> None:
    assert _wb_clock_verifies(backup_time, "11/14/2026-07:32", offset, _utc(2026, 11, 14, 7, 0)) is False


def test_the_offsets_at_the_ends_of_the_range_verify() -> None:
    at = _utc(2026, 11, 14, 7, 0)
    assert _wb_clock_verifies("11/15/2026 7:31 AM", "11/14/2026-07:32", 1439, at) is True
    assert _wb_clock_verifies("11/13/2026 7:33 AM", "11/14/2026-07:32", -1439, at) is True


@pytest.mark.parametrize(
    "backup_time",
    [
        "11/14/2026 13:32 PM",
        "11/14/2026 0:32 AM",
        "11/14/2026 07:32 AM",  # measured unpadded
        "11/31/2026 7:32 AM",  # no such day
        "11/04/2026 7:32 AM",  # measured unpadded
        "11/0/2026 7:32 AM",
        "11/14/2026 7:60 AM",
        "11/14/2026 7:32 am",
        "11/14/2026 7:32",
    ],
)
def test_an_unparsable_backup_time_is_unverified(backup_time: str) -> None:
    text = _wb_clock(backup_time, "11/14/2026-07:32")
    with pytest.raises(ValueError):
        checkpoint.parse_wbadmin_versions(text)
    assert _wb_clock_verifies(backup_time, "11/14/2026-07:32", 0, _utc(2026, 11, 14, 7, 0)) is False


def test_the_wbadmin_checkpoint_takes_the_all_critical_backup() -> None:
    taken: list[tuple[str, str]] = []
    adapter = checkpoint.WbadminAdapter(
        read_versions=lambda s: checkpoint.WbadminRead(computer="BDC1", text="", utc_offset_minutes=0),
        read_genid=lambda s: GENID_PRESENT,
        take=lambda server_cfg, backup: taken.append((server_cfg["device"], backup)) or "11/14/2026-07:58",
    )
    for kind in ("workgroup", "dc"):
        cp = adapter.checkpoint(WB_SERVER, kind)
        assert cp["id"] == "11/14/2026-07:58"
        assert plan.CHECKPOINT_ID_RE.fullmatch(cp["id"])
        assert set(cp) == {"name", "id"}
    assert taken == [("build1", "allCritical"), ("build1", "allCritical")]


# -- the generation id read ---------------------------------------------------------


def test_the_generation_id_read_is_the_one_of_stage_2() -> None:
    assert checkpoint.genid_present(GENID_PRESENT, hostname="BDC1") is True
    assert checkpoint.genid_present(GENID_PRESENT, hostname="bdc1") is True
    assert checkpoint.genid_present(GENID_ABSENT, hostname="BDC1") is False
    assert checkpoint.genid_present(GENID_PRESENT, hostname="BDC2") is False
    twice = GENID_PRESENT + GENID_PRESENT
    assert checkpoint.genid_present(twice, hostname="BDC1") is False
    short = GENID_PRESENT.replace("8 bytes, dfff81575195ab49", "4 bytes, dfff8157")
    assert checkpoint.genid_present(short, hostname="BDC1") is False
    assert checkpoint.genid_present(None, hostname="BDC1") is False  # type: ignore[arg-type]


# -- the dispatcher and the stop of the run -----------------------------------------


class _Says:
    def __init__(self, answer: Any) -> None:
        self.answer = answer
        self.calls: list[tuple[str, str]] = []

    def verify(self, server_cfg: Any, cp: Any, kind: str, *, stage: str, not_before: int) -> Any:
        self.calls.append((kind, stage, not_before))
        if isinstance(self.answer, BaseException):
            raise self.answer
        return self.answer

    def checkpoint(self, server_cfg: Any, kind: str) -> dict[str, str]:
        if isinstance(self.answer, BaseException):
            raise self.answer
        return {"name": "n", "id": "i"}


def test_the_adapters_dispatch_on_the_method_of_the_server() -> None:
    yes, no = _Says(True), _Says(False)
    adapters = checkpoint.CheckpointAdapters({"proxmox": yes, "hyperv": no})
    assert adapters.verify(PVE_SERVER, {"name": "n", "id": "i"}, "dc", stage="3", not_before=RUN2_STAGE2_DONE) is True
    assert adapters.verify(dict(PVE_SERVER, checkpoint="hyperv"), {"name": "n", "id": "i"}, "dc", stage="3", not_before=RUN2_STAGE2_DONE) is False
    assert adapters.verify(dict(PVE_SERVER, checkpoint="wbadmin"), {"name": "n", "id": "i"}, "dc", stage="3", not_before=RUN2_STAGE2_DONE) is False
    assert yes.calls == [("dc", "3", RUN2_STAGE2_DONE)]
    with pytest.raises(TypeError):
        adapters.verify(PVE_SERVER, {"name": "n", "id": "i"}, "dc", stage="3")  # type: ignore[call-arg]
    assert adapters.checkpoint(PVE_SERVER, "dc") == {"name": "n", "id": "i"}
    with pytest.raises(checkpoint.CheckpointUnverified):
        adapters.checkpoint(dict(PVE_SERVER, checkpoint="wbadmin"), "dc")


def test_an_unverified_checkpoint_stops_the_run_with_checkpoint_unverified() -> None:
    cp = {"name": "n", "id": "i"}
    says = _Says(True)
    checkpoint.require_verified(says, PVE_SERVER, cp, "dc", stage="3", not_before=RUN2_STAGE2_DONE)
    assert says.calls == [("dc", "3", RUN2_STAGE2_DONE)]
    for answer in (False, None, 1, "yes", OSError("down")):
        with pytest.raises(checkpoint.CheckpointUnverified) as caught:
            checkpoint.require_verified(_Says(answer), PVE_SERVER, cp, "dc", stage="3", not_before=RUN2_STAGE2_DONE)
        assert caught.value.code == "checkpoint_unverified"
    assert "checkpoint_unverified" in approve.BUILD_REFUSAL_CODES
    # the bound is passed on every call: no default
    with pytest.raises(TypeError):
        checkpoint.require_verified(_Says(True), PVE_SERVER, cp, "dc", stage="3")  # type: ignore[call-arg]


def test_a_checkpoint_that_raises_stops_the_run_with_checkpoint_unverified() -> None:
    """The dispatcher's checkpoint turns an adapter that raises into
    checkpoint_unverified, as require_verified does (m3 of the triage)."""
    for exc in (OSError("down"), ValueError("bad"), KeyError("x"), RuntimeError("r")):
        adapters = checkpoint.CheckpointAdapters({"proxmox": _Says(exc)})
        with pytest.raises(checkpoint.CheckpointUnverified) as caught:
            adapters.checkpoint(PVE_SERVER, "dc")
        assert caught.value.code == "checkpoint_unverified"
        assert caught.value.__cause__ is None and caught.value.__suppress_context__ is True


def test_the_kind_of_each_stage_is_the_one_of_the_approval() -> None:
    assert checkpoint.KIND_OF_STAGE == approve.BUILD_CHECKPOINT_OF_STAGE


# -- hv-checkpoint.ps1, the forced command of the Hyper-V host ----------------------


HV_SCRIPT = (
    Path(__file__).resolve().parents[3]
    / "newton_mcp" / "ad" / "build" / "helper" / "hv-checkpoint.ps1"
)

#: The fake Hyper-V of the tests: Get-VM, Set-VM, Checkpoint-VM and
#: Get-VMSnapshot over a JSON state file, each call recorded.  The
#: functions shadow the Hyper-V cmdlets inside the script.
HV_WRAPPER = r"""
param([string]$Script, [string]$State, [string]$Allow, [string]$Calls)
$ErrorActionPreference = 'Stop'
$global:NewtonFakeSt = Get-Content -Raw -LiteralPath $State | ConvertFrom-Json
$global:NewtonFakeLog = New-Object System.Collections.Generic.List[string]
function Save-Fake { [IO.File]::WriteAllText($Calls, (ConvertTo-Json -InputObject @($global:NewtonFakeLog.ToArray()))); [IO.File]::WriteAllText($State, (ConvertTo-Json -InputObject $global:NewtonFakeSt -Depth 5)) }
function Get-VM { param([string]$Name) $global:NewtonFakeLog.Add('Get-VM ' + $Name); foreach ($v in @($global:NewtonFakeSt.vms)) { if ($v.Name -like $Name) { [pscustomobject]@{ Name = $v.Name; CheckpointType = $v.CheckpointType } } } }
function Set-VM { param([string]$Name, $VM, [string]$CheckpointType) if ($VM) { $Name = $VM.Name; $match = { param($n) $n -ceq $VM.Name } } else { $match = { param($n) $n -like $Name } }; $global:NewtonFakeLog.Add('Set-VM ' + $Name + ' ' + $CheckpointType); foreach ($v in @($global:NewtonFakeSt.vms)) { if (& $match $v.Name) { $v.CheckpointType = $CheckpointType } } }
function Checkpoint-VM { param([string]$Name, $VM, [string]$SnapshotName)
  if ($VM) { $targets = @($VM.Name) } else { $targets = @(@($global:NewtonFakeSt.vms) | Where-Object { $_.Name -like $Name } | ForEach-Object { $_.Name }) }
  foreach ($t in $targets) {
    $global:NewtonFakeLog.Add('Checkpoint-VM ' + $t + ' ' + $SnapshotName)
    if ($global:NewtonFakeSt.fail_create) { throw 'the checkpoint failed' }
    $global:NewtonFakeSt.snapshots = @($global:NewtonFakeSt.snapshots) + @([pscustomobject]@{ VMName = $t; Name = $SnapshotName; Id = $global:NewtonFakeSt.next_id; CreationTime = $global:NewtonFakeSt.next_time }) } }
function Get-VMSnapshot { param([string]$VMName, $VM) if ($VM) { $VMName = $VM.Name; $exact = $true } else { $exact = $false }; $global:NewtonFakeLog.Add('Get-VMSnapshot ' + $VMName)
  foreach ($s in @($global:NewtonFakeSt.snapshots)) { if (($exact -and ($s.VMName -ceq $VMName)) -or ((-not $exact) -and ($s.VMName -like $VMName))) { [pscustomobject]@{ VMName = $s.VMName; Name = $s.Name; Id = [guid]$s.Id; CreationTime = [datetime]::SpecifyKind([datetime]::Parse($s.CreationTime, [Globalization.CultureInfo]::InvariantCulture), $(if ($s.PSObject.Properties['Kind']) { $s.Kind } else { 'Utc' })); SnapshotType = 'Standard' } } } }
try { & $Script -AllowlistPath $Allow; $rc = $LASTEXITCODE } finally { Save-Fake }
exit $rc
"""

HV_STATE: dict[str, Any] = {
    "vms": [
        {"Name": "BUILD1", "CheckpointType": "Standard"},
        {"Name": "OTHER", "CheckpointType": "Standard"},
    ],
    "snapshots": [
        {
            "VMName": "BUILD1",
            "Name": "build1-fresh-workgroup",
            "Id": "3f2b1c4d-5e6f-4a8b-9c0d-1e2f3a4b5c6d",
            "CreationTime": "2026-11-10T22:10:05",
        },
        {
            "VMName": "OTHER",
            "Name": "other-1",
            "Id": "0d8e7f6a-5b4c-4d3e-8f2a-1b0c9d8e7f6a",
            "CreationTime": "2026-11-10T22:11:00",
        },
    ],
    "next_id": "6a5b4c3d-2e1f-4a0b-9c8d-7e6f5a4b3c2d",
    "next_time": "2026-11-11T00:23:51",
    "fail_create": False,
}


def _hv(
    tmp_path: Path,
    command: str | None,
    *,
    state: dict[str, Any] | None = None,
    allow: str = "BUILD1\n",
    tz: str | None = None,
) -> tuple[int, str, list[str], dict[str, Any]]:
    if not PWSH.is_file():
        pytest.skip(f"PowerShell is not installed at {PWSH}")
    wrapper = tmp_path / "hv-wrapper.ps1"
    wrapper.write_text(HV_WRAPPER, encoding="utf-8")
    state_file = tmp_path / "hv-state.json"
    state_file.write_text(_json.dumps(state or HV_STATE), encoding="utf-8")
    allow_file = tmp_path / "vm.txt"
    allow_file.write_text(allow, encoding="utf-8")
    calls_file = tmp_path / "hv-calls.json"
    env = {k: v for k, v in os.environ.items() if k != "SSH_ORIGINAL_COMMAND"}
    if command is not None:
        env["SSH_ORIGINAL_COMMAND"] = command
    if tz is not None:
        env["TZ"] = tz
    done = subprocess.run(
        [str(PWSH), "-NoProfile", "-NonInteractive", "-File", str(wrapper),
         "-Script", str(HV_SCRIPT), "-State", str(state_file),
         "-Allow", str(allow_file), "-Calls", str(calls_file)],
        capture_output=True, text=True, timeout=60, check=False, env=env,
    )
    calls = _json.loads(calls_file.read_text(encoding="utf-8")) if calls_file.exists() else []
    return done.returncode, done.stdout, list(calls or []), _json.loads(state_file.read_text(encoding="utf-8"))


def test_hv_checkpoint_lists_one_snapshot_as_a_json_array(tmp_path: Path) -> None:
    rc, out, calls, _ = _hv(tmp_path, "list BUILD1")
    assert rc == 0, out
    listed = _json.loads(out)
    assert isinstance(listed, list) and len(listed) == 1
    assert listed[0] == {
        "name": "build1-fresh-workgroup",
        "id": "3f2b1c4d-5e6f-4a8b-9c0d-1e2f3a4b5c6d",
        "created": "2026-11-10T22:10:05Z",
        "vm": "BUILD1",
        "checkpoint_type": "Standard",
    }
    assert out.endswith("\n") and out.count("\n") == 1


def test_hv_checkpoint_turns_a_local_creation_time_to_utc(tmp_path: Path) -> None:
    """W2 of the ccdd15e review.  The fakes above hand the script a
    Utc-kind CreationTime; Get-VMSnapshot is expected to give a Local-kind
    one (its Kind on a real Hyper-V host, under PowerShell 5.1 and 7, is
    unmeasured: DESIGN-1.5 task 7 open point 8).  On a host at UTC-5 a
    Local 17:10:05 is 22:10:05Z."""
    state = copy.deepcopy(HV_STATE)
    state["snapshots"][0] = dict(state["snapshots"][0], CreationTime="2026-11-10T17:10:05", Kind="Local")
    rc, out, _, _ = _hv(tmp_path, "list BUILD1", state=state, tz="America/New_York")
    assert rc == 0, out
    (listed,) = _json.loads(out)
    assert listed["created"] == "2026-11-10T22:10:05Z"


def test_hv_checkpoint_lists_no_snapshot_as_an_empty_array(tmp_path: Path) -> None:
    state = copy.deepcopy(HV_STATE)
    state["snapshots"] = [s for s in state["snapshots"] if s["VMName"] != "BUILD1"]
    rc, out, _, _ = _hv(tmp_path, "list BUILD1", state=state)
    assert rc == 0
    assert _json.loads(out) == []


def test_hv_checkpoint_creates_a_production_checkpoint(tmp_path: Path) -> None:
    rc, out, calls, state = _hv(tmp_path, "create BUILD1 newton-dc-20261111-002351")
    assert rc == 0, out
    made = _json.loads(out)
    assert made == {
        "name": "newton-dc-20261111-002351",
        "id": "6a5b4c3d-2e1f-4a0b-9c8d-7e6f5a4b3c2d",
        "created": "2026-11-11T00:23:51Z",
        "vm": "BUILD1",
        "checkpoint_type": "ProductionOnly",
    }
    assert calls.index("Set-VM BUILD1 ProductionOnly") < calls.index(
        "Checkpoint-VM BUILD1 newton-dc-20261111-002351"
    )


@pytest.mark.parametrize(
    "command",
    [
        "list OTHER",
        "create OTHER newton-dc-1",
        "list build1",
        "list BUILD1 BUILD1",
        "list BUILD1;whoami",
        "create BUILD1 a;b",
        "create BUILD1",
        "cmd /c whoami",
        "list  BUILD1",
        "list BUILD1 ",
        "restore BUILD1 build1-fresh-workgroup",
        "remove BUILD1 build1-fresh-workgroup",
        "list *",
        "list BUILD*",
        "",
        None,
    ],
)
def test_hv_checkpoint_refuses_everything_else(tmp_path: Path, command: str | None) -> None:
    rc, out, calls, state = _hv(tmp_path, command)
    assert rc != 0
    assert out == "refused\n"
    assert calls == []
    assert state["snapshots"] == HV_STATE["snapshots"]


def test_hv_checkpoint_refuses_a_vm_outside_its_allowlist(tmp_path: Path) -> None:
    for allow in ("", "OTHER\n", "BUILD10\n", "# BUILD1\n"):
        rc, out, calls, _ = _hv(tmp_path, "list BUILD1", allow=allow)
        assert (rc, out, calls) == (1, "refused\n", [])
    rc, out, _, _ = _hv(tmp_path, "list BUILD1", allow="OTHER\r\nBUILD1\r\n")
    assert rc == 0


def test_hv_checkpoint_refuses_a_name_already_taken(tmp_path: Path) -> None:
    rc, out, calls, state = _hv(tmp_path, "create BUILD1 build1-fresh-workgroup")
    assert (rc, out) == (1, "refused\n")
    assert not any(c.startswith("Checkpoint-VM") for c in calls)


def test_hv_checkpoint_says_failed_when_the_checkpoint_fails(tmp_path: Path) -> None:
    state = dict(copy.deepcopy(HV_STATE), fail_create=True)
    rc, out, _, _ = _hv(tmp_path, "create BUILD1 newton-dc-1", state=state)
    assert rc == 2
    assert out == "failed\n"


# -- the Hyper-V adapter ------------------------------------------------------------

HV_SERVER: dict[str, Any] = {"device": "build1", "role": "dc1", "hostname": "BDC1", "checkpoint": "hyperv"}

#: 2026-11-11T00:00:00Z: a plan approval before the fake host's next
#: checkpoint (2026-11-11T00:23:51Z).
HV_NBF = int(datetime(2026, 11, 11, tzinfo=timezone.utc).timestamp())

HV_SSH = ("ssh", "-i", "/home/owner/.ssh/hv-checkpoint", "-o", "BatchMode=yes", "hv-checkpoint@hvhost.example.test")


class FakeHvHost:
    """hv-checkpoint.ps1 run under pwsh with the fake Hyper-V: the
    adapter's argv reaches the script as SSH_ORIGINAL_COMMAND, the way
    sshd hands a forced command the client's words."""

    def __init__(self, tmp_path: Path, state: dict[str, Any] | None = None) -> None:
        self.tmp_path = tmp_path
        self.state = copy.deepcopy(state or HV_STATE)
        self.argvs: list[list[str]] = []

    def __call__(self, argv: Any) -> tuple[int, str]:
        assert isinstance(argv, list) and all(isinstance(a, str) for a in argv)
        self.argvs.append(list(argv))
        assert tuple(argv[: len(HV_SSH)]) == HV_SSH
        rc, out, _, self.state = _hv(self.tmp_path, " ".join(argv[len(HV_SSH):]), state=self.state)
        return rc, out


def _hv_adapter(host: Any, *, genid: str = GENID_PRESENT, showbackup: Any = None, at: datetime | None = None) -> Any:
    return checkpoint.HyperVAdapter(
        {"build1": checkpoint.HyperVTarget(ssh=HV_SSH, vm="BUILD1")},
        run=host,
        read_genid=lambda s: genid,
        read_showbackup=showbackup or (lambda s: (_ for _ in ()).throw(OSError("no read"))),
        clock=lambda: at or datetime(2026, 11, 11, 0, 23, 51, tzinfo=timezone.utc),
    )


def test_the_hyperv_checkpoint_and_its_workgroup_verify(tmp_path: Path) -> None:
    host = FakeHvHost(tmp_path)
    adapter = _hv_adapter(host)
    cp = adapter.checkpoint(HV_SERVER, "workgroup")
    assert cp == {"name": "newton-workgroup-20261111-002351", "id": "6a5b4c3d-2e1f-4a0b-9c8d-7e6f5a4b3c2d"}
    assert host.argvs[0] == [*HV_SSH, "create", "BUILD1", "newton-workgroup-20261111-002351"]
    assert adapter.verify(HV_SERVER, cp, "workgroup", stage="2", not_before=HV_NBF) is True
    assert host.argvs[1] == [*HV_SSH, "list", "BUILD1"]


def test_a_hyperv_checkpoint_not_listed_or_not_production_is_unverified(tmp_path: Path) -> None:
    host = FakeHvHost(tmp_path)
    adapter = _hv_adapter(host)
    cp = adapter.checkpoint(HV_SERVER, "workgroup")
    assert adapter.verify(HV_SERVER, dict(cp, id="0d8e7f6a-5b4c-4d3e-8f2a-1b0c9d8e7f6a"), "workgroup", stage="2", not_before=HV_NBF) is False
    assert adapter.verify(HV_SERVER, dict(cp, name="other"), "workgroup", stage="2", not_before=HV_NBF) is False
    for vm in host.state["vms"]:
        vm["CheckpointType"] = "Production"
    assert adapter.verify(HV_SERVER, cp, "workgroup", stage="2", not_before=HV_NBF) is False


def test_a_hyperv_list_that_is_not_an_array_is_unverified(tmp_path: Path) -> None:
    listed = {"name": "newton-workgroup-1", "id": "6a5b4c3d-2e1f-4a0b-9c8d-7e6f5a4b3c2d", "created": "2026-11-11T00:23:51Z", "vm": "BUILD1", "checkpoint_type": "ProductionOnly"}
    cp = {"name": listed["name"], "id": listed["id"]}
    for rc, out in ((0, _json.dumps(listed)), (0, _json.dumps([listed])), (1, "refused\n"), (0, "[" + _json.dumps(listed) + "," + _json.dumps(listed) + "]")):
        adapter = _hv_adapter(lambda argv, rc=rc, out=out: (rc, out))
        verdict = adapter.verify(HV_SERVER, cp, "workgroup", stage="2", not_before=HV_NBF)
        assert verdict is (rc == 0 and out == _json.dumps([listed]))


def test_a_skip_line_in_the_place_of_the_freeze_is_refused() -> None:
    """The freeze must be the first line itself, not only some line
    before a thaw (mutant G1)."""
    lines = _log_lines("pve-dcagent-log.json")
    ok = dict(vmid="731", snapname="m7-dc")
    assert checkpoint.proxmox_log_verifies(lines, **ok) is True
    for first in (
        "skipping guest filesystem freeze - agent configured but not running?",
        "freeze guest filesystem ",
        "Freeze guest filesystem",
    ):
        assert checkpoint.proxmox_log_verifies([first] + lines[1:], **ok) is False


def test_a_line_inside_one_disk_s_lines_is_refused() -> None:
    """A line that is not a thin-pool line is refused between a disk's
    snapshotting line and its volume line too (mutant G2)."""
    lines = _log_lines("pve-dcagent-log.json")
    ok = dict(vmid="731", snapname="m7-dc")
    first_disk = lines.index("snapshotting 'drive-sata0' (vmdata:vm-731-disk-0)")
    for extra in (
        "unable to freeze guest fs - failed to initialize for backup: Windows error 0x80042302: ",
        "  WARNING: something else entirely",
        "snapshotting 'drive-sata2' (vmdata:vm-731-disk-1)",
    ):
        changed = lines[: first_disk + 1] + [extra] + lines[first_disk + 1 :]
        assert checkpoint.proxmox_log_verifies(changed, **ok) is False


def test_the_adapters_answer_only_true_or_false() -> None:
    """An adapter's truthy answer that is not True never verifies
    through the dispatcher (mutant G25)."""
    for answer in (1, "yes", [True], object()):
        adapters = checkpoint.CheckpointAdapters({"proxmox": _Says(answer)})
        assert adapters.verify(PVE_SERVER, {"name": "n", "id": "i"}, "dc", stage="3", not_before=RUN2_STAGE2_DONE) is False


# -- repadmin /showbackup, the Hyper-V DC read-back -------------------------------

#: The partitions of the BUILD1 forest (MEASURED-1.5, all five).
BUILD_PARTITIONS = [
    "DC=ForestDnsZones,DC=build,DC=newton,DC=test",
    "DC=DomainDnsZones,DC=build,DC=newton,DC=test",
    "CN=Schema,CN=Configuration,DC=build,DC=newton,DC=test",
    "CN=Configuration,DC=build,DC=newton,DC=test",
    "DC=build,DC=newton,DC=test",
]


def test_showbackup_is_parsed_as_measured() -> None:
    before = checkpoint.parse_showbackup(_text("repadmin-showbackup-before.txt"))
    assert list(before) == BUILD_PARTITIONS
    assert set(before.values()) == {None}
    after = checkpoint.parse_showbackup(_text("repadmin-showbackup-ss.txt"))
    assert list(after) == BUILD_PARTITIONS
    assert set(after.values()) == {datetime(2026, 11, 14, 7, 31, 8)}
    # a Proxmox snapshot records no backup (MEASURED-1.5 section 7, again on BUILD1)
    assert checkpoint.parse_showbackup(_text("repadmin-showbackup-dc.txt")) == before


@pytest.mark.parametrize(
    "mangle",
    [
        lambda t: t.replace("Repadmin: running command /showbackup against full DC localhost", "Repadmin: error"),
        lambda t: t.replace(" dSASignature", " dSASignature2", 1),
        lambda t: t.replace("2026-11-14 07:31:08", "2026-11-14 7:31:08", 1),
        lambda t: t + "  16579      b8de3f20-e4b5-4bf3-b93c-9e285d6b2143     16579 2026-11-14 07:31:08    1 dSASignature\n",
        lambda t: t.replace("=======", "-------", 1),
        lambda t: t + "something else\n",
    ],
)
def test_a_showbackup_outside_the_measured_shape_is_refused(mangle: Any) -> None:
    text = _text("repadmin-showbackup-ss.txt")
    checkpoint.parse_showbackup(text)
    with pytest.raises(ValueError):
        checkpoint.parse_showbackup(mangle(text))


def test_every_partition_must_be_backed_up_no_older_than_the_checkpoint() -> None:
    text = _text("repadmin-showbackup-ss.txt")
    at = datetime(2026, 11, 14, 7, 31, 8, tzinfo=timezone.utc)
    read = checkpoint.ShowbackupRead(text, 0)
    assert checkpoint.dsa_signatures_no_older(read, at) is True
    assert checkpoint.dsa_signatures_no_older(read, at.replace(second=9)) is False
    # repadmin prints the DC's local time: a DC at UTC-10 stamped 07:31:08 local is 17:31:08 UTC
    assert checkpoint.dsa_signatures_no_older(checkpoint.ShowbackupRead(text, -600), at.replace(hour=17)) is True
    assert checkpoint.dsa_signatures_no_older(checkpoint.ShowbackupRead(text, -600), at.replace(hour=17, second=9)) is False
    # no backup at all
    before = checkpoint.ShowbackupRead(_text("repadmin-showbackup-before.txt"), 0)
    assert checkpoint.dsa_signatures_no_older(before, at.replace(year=2020)) is False
    # one partition older
    one_old = text.replace("16576 2026-11-14 07:31:08", "16576 2026-11-14 07:01:08")
    assert checkpoint.dsa_signatures_no_older(checkpoint.ShowbackupRead(one_old, 0), at) is False
    # a partition missing: the schema
    lines = [line for line in text.split("\n") if line.strip()]
    for gone in (
        "CN=Schema,CN=Configuration,DC=build,DC=newton,DC=test",
        "CN=Configuration,DC=build,DC=newton,DC=test",
        "DC=build,DC=newton,DC=test",
    ):
        i = lines.index(gone)
        without = "\n".join(lines[:i] + lines[i + 2 :]) + "\n"
        checkpoint.parse_showbackup(without)
        assert checkpoint.dsa_signatures_no_older(checkpoint.ShowbackupRead(without, 0), at) is False
    assert checkpoint.dsa_signatures_no_older(checkpoint.ShowbackupRead("garbage", 0), at) is False
    assert checkpoint.dsa_signatures_no_older(checkpoint.ShowbackupRead(text, True), at) is False  # type: ignore[arg-type]


def test_a_hyperv_dc_checkpoint_needs_the_backup_and_the_generation_id(tmp_path: Path) -> None:
    at = datetime(2026, 11, 14, 7, 31, 8, tzinfo=timezone.utc)
    state = copy.deepcopy(HV_STATE)
    state["next_time"] = "2026-11-14T07:31:08"
    ss = checkpoint.ShowbackupRead(_text("repadmin-showbackup-ss.txt"), 0)
    before = checkpoint.ShowbackupRead(_text("repadmin-showbackup-before.txt"), 0)
    host = FakeHvHost(tmp_path, state)
    cp = _hv_adapter(host, at=at).checkpoint(HV_SERVER, "dc")
    assert _hv_adapter(host, showbackup=lambda s: ss).verify(HV_SERVER, cp, "dc", stage="3", not_before=RUN2_STAGE2_DONE) is True
    assert _hv_adapter(host, showbackup=lambda s: before).verify(HV_SERVER, cp, "dc", stage="3", not_before=RUN2_STAGE2_DONE) is False
    assert _hv_adapter(host, showbackup=lambda s: ss, genid=GENID_ABSENT).verify(HV_SERVER, cp, "dc", stage="3", not_before=RUN2_STAGE2_DONE) is False
    # a read that fails is an adapter that cannot answer
    with pytest.raises(OSError):
        _hv_adapter(host).verify(HV_SERVER, cp, "dc", stage="3", not_before=RUN2_STAGE2_DONE)


def test_the_dc_backups_of_build1_read_as_measured() -> None:
    """The two backups of the promoted BUILD1 (2026-11-14): the version
    identifier is the minute a backup started, and its dSASignature the
    second it ended."""
    versions = checkpoint.parse_wbadmin_versions(_text("wbadmin-versions-dc-ac.txt"))
    assert [(v.identifier, v.can_recover[-2:]) for v in versions] == [
        ("11/14/2026-07:19", ("Application(s)", "System State")),
        ("11/14/2026-07:32", ("Bare Metal Recovery", "System State")),
    ]
    assert [v.identifier for v in checkpoint.parse_wbadmin_versions(_text("wbadmin-versions-dc-ss.txt"))] == [
        "11/14/2026-07:19"
    ]
    after = checkpoint.parse_showbackup(_text("repadmin-showbackup-ac.txt"))
    assert set(after.values()) == {datetime(2026, 11, 14, 7, 33, 25)}
    adapter = _wb_adapter(_text("wbadmin-versions-dc-ac.txt"))
    ss, ac = WB_DC_SS, WB_DC_AC
    ok = dict(not_before=RUN2_STAGE2_DONE)
    assert [adapter.verify(WB_SERVER, ss, "dc", stage=s, **ok) for s in ("3", "4", "6", "7")] == [True, True, True, False]
    assert [adapter.verify(WB_SERVER, ac, "dc", stage=s, **ok) for s in ("3", "4", "6", "7")] == [True, True, True, True]
    # the workgroup versions of 2026-11-13 are older than the 2026-11-14 approval
    old = _wb_adapter(_text("wbadmin-versions-workgroup-ac.txt"))
    assert old.verify(WB_SERVER, {"name": "w", "id": "11/13/2026-06:58"}, "workgroup", stage="2", not_before=RUN2_NBF) is False


def test_hv_checkpoint_writes_only_the_allowlisted_vm_of_its_exact_name(tmp_path: Path) -> None:
    """The Hyper-V cmdlets match -Name case-insensitively: a VM Build1
    beside the allowlisted BUILD1 is never changed nor checkpointed
    (review finding 2)."""
    state = copy.deepcopy(HV_STATE)
    state["vms"].append({"Name": "Build1", "CheckpointType": "Standard"})
    rc, out, calls, after = _hv(tmp_path, "create BUILD1 newton-dc-1", state=state)
    assert rc == 0, out
    other = [v for v in after["vms"] if v["Name"] == "Build1"][0]
    assert other["CheckpointType"] == "Standard"
    assert [s for s in after["snapshots"] if s["VMName"] == "Build1"] == []
    assert calls.count("Checkpoint-VM BUILD1 newton-dc-1") == 1
    assert not any(c.startswith("Checkpoint-VM Build1") for c in calls)


def test_the_dns_partitions_must_be_backed_up_too() -> None:
    """Every partition of the forest root: the two DNS application
    partitions as well (review finding 1)."""
    text = _text("repadmin-showbackup-ss.txt")
    at = datetime(2026, 11, 14, 7, 31, 8, tzinfo=timezone.utc)
    lines = [line for line in text.split("\n") if line.strip()]
    for gone in (
        ["DC=ForestDnsZones,DC=build,DC=newton,DC=test"],
        ["DC=DomainDnsZones,DC=build,DC=newton,DC=test"],
        ["DC=ForestDnsZones,DC=build,DC=newton,DC=test", "DC=DomainDnsZones,DC=build,DC=newton,DC=test"],
    ):
        kept = list(lines)
        for name in gone:
            i = kept.index(name)
            kept = kept[:i] + kept[i + 2 :]
        without = "\n".join(kept) + "\n"
        checkpoint.parse_showbackup(without)
        assert checkpoint.dsa_signatures_no_older(checkpoint.ShowbackupRead(without, 0), at) is False
    extra = text + "DC=Other,DC=build,DC=newton,DC=test\n  16579      b8de3f20-e4b5-4bf3-b93c-9e285d6b2143     16579 2026-11-14 07:31:08    1 dSASignature\n"
    assert checkpoint.dsa_signatures_no_older(checkpoint.ShowbackupRead(extra, 0), at) is False


def test_a_disk_snapshotted_twice_is_refused() -> None:
    """Each disk once: a log that snapshots one disk twice is not the
    measured shape (review finding 3)."""
    lines = _log_lines("pve-dcagent-log.json")
    ok = dict(vmid="731", snapname="m7-dc")
    second = lines.index("snapshotting 'drive-sata2' (vmdata:vm-731-disk-1)")
    thaw = lines.index("thaw guest filesystem")
    first_block = lines[1:second]
    twice = [lines[0]] + first_block + first_block + lines[thaw:]
    assert checkpoint.proxmox_log_verifies(twice, **ok) is False


def test_a_thin_pool_line_before_the_first_disk_is_refused() -> None:
    """A thin-pool line comes only after a disk's snapshotting line
    (review finding 4, the ``disks == 0`` guard)."""
    lines = _log_lines("pve-dcagent-log.json")
    ok = dict(vmid="731", snapname="m7-dc")
    pruning = [line for line in lines if line.startswith("  Consider pruning")][0]
    assert checkpoint.proxmox_log_verifies(lines[:1] + [pruning] + lines[1:], **ok) is False


def test_a_snapshot_whose_vmstate_is_a_json_boolean_is_unverified(tmp_path: Path) -> None:
    """``false`` equals 0 in Python: a vmstate that is a JSON boolean is
    not the measured integer (review finding 4)."""
    cp = _pve_cp("dcagent")
    answers = _pve_answers("dcagent")
    key = ("GET", "/nodes/Apollo/qemu/731/snapshot")
    for snap in answers[key]["data"]:
        if snap["name"] == cp["name"]:
            snap["vmstate"] = False
    assert _pve_adapter(tmp_path, FakePve(answers)).verify(PVE_SERVER, cp, "dc", stage="3", not_before=RUN2_STAGE2_DONE) is False


# -- the bound: a checkpoint taken before the stage it follows (B1, M1) --------
#
# A DC checkpoint must be taken after the later of the plan approval's NBF
# and the recorded completion of the stage before (the caller passes it on
# every verify call): stage 2's pre-promotion snapshot, with its good
# freeze lines and the genid the DC holds by now, or a snapshot of an
# earlier run, is never the DC checkpoint of a later stage.


def _pve_verify(
    tmp_path: Path,
    case: str,
    kind: str,
    stage: str,
    bound: Any,
    *,
    answers: dict[tuple[str, str], Any] | None = None,
    cp: dict[str, str] | None = None,
) -> Any:
    adapter = _pve_adapter(tmp_path, FakePve(answers if answers is not None else _pve_answers(case)))
    return adapter.verify(PVE_SERVER, cp or _pve_cp(case), kind, stage=stage, not_before=bound)


def test_a_pre_promotion_proxmox_snapshot_is_never_a_dc_checkpoint(tmp_path: Path) -> None:
    """m7-wg: the workgroup snapshot of the 2026-11-14 run, freeze and thaw
    as measured; the DC it became holds msDS-GenerationId at verify time.
    The control shows every other check passes it: only the bound refuses."""
    assert _pve_verify(tmp_path, "wg", "dc", "3", RUN2_NBF) is True  # control
    for stage in ("3", "4", "6", "7"):
        assert _pve_verify(tmp_path, "wg", "dc", stage, RUN2_STAGE2_DONE) is False


def test_a_proxmox_snapshot_of_an_earlier_run_is_unverified(tmp_path: Path) -> None:
    """m-disk-1 (2026-11-13) is older than the 2026-11-14 run's approval."""
    assert _pve_verify(tmp_path, "agent", "workgroup", "2", RUN1_NBF) is True  # control
    assert _pve_verify(tmp_path, "agent", "workgroup", "2", RUN2_NBF) is False
    assert _pve_verify(tmp_path, "agent", "dc", "3", RUN2_STAGE2_DONE) is False


def test_a_proxmox_dc_snapshot_of_an_earlier_stage_is_unverified(tmp_path: Path) -> None:
    """m7-dc (07:18:09Z) verifies at the bound and not one second after
    it, so stage 3's checkpoint is not stage 6's once stage 5 is done."""
    taken = 1794640689
    assert _pve_verify(tmp_path, "dcagent", "dc", "3", taken) is True
    assert _pve_verify(tmp_path, "dcagent", "dc", "3", taken + 1) is False
    stage5_done = int(datetime(2026, 11, 14, 7, 40, tzinfo=timezone.utc).timestamp())
    assert _pve_verify(tmp_path, "dcagent", "dc", "6", stage5_done) is False


def test_the_proxmox_snaptime_must_meet_the_bound(tmp_path: Path) -> None:
    """The snapshot's snaptime is read on its own: a listed snapshot older
    than the bound, or with no snaptime of the measured type, is
    unverified even when its task's UPID starttime meets the bound."""
    cp = _pve_cp("dcagent")
    key = ("GET", "/nodes/Apollo/qemu/731/snapshot")
    for snaptime in (RUN2_STAGE2_DONE - 1, None, "1794640689", True, 1794640689.0, "missing"):
        answers = _pve_answers("dcagent")
        for snap in answers[key]["data"]:
            if snap["name"] == cp["name"]:
                if snaptime == "missing":
                    del snap["snaptime"]
                else:
                    snap["snaptime"] = snaptime
        assert _pve_verify(tmp_path, "dcagent", "dc", "3", RUN2_STAGE2_DONE, answers=answers) is False


def test_the_proxmox_upid_starttime_must_meet_the_bound(tmp_path: Path) -> None:
    """The task's UPID starttime is read on its own: a task that started
    before the bound is unverified even when the listed snaptime meets it."""
    cp = _pve_cp("dcagent")
    start_hex = cp["id"].split(":")[4]
    assert int(start_hex, 16) == 1794640689

    def started(at: int) -> tuple[dict[tuple[str, str], Any], dict[str, str]]:
        upid = cp["id"].replace(f":{start_hex}:", f":{at:08X}:")
        answers = _pve_answers("dcagent", upid=upid)
        status = [k for k in answers if k[1].endswith("/status")][0]
        answers[status]["data"]["upid"] = upid
        return answers, dict(cp, id=upid)

    answers, forged = started(RUN2_STAGE2_DONE)
    assert _pve_verify(tmp_path, "dcagent", "dc", "3", RUN2_STAGE2_DONE, answers=answers, cp=forged) is True  # control
    answers, forged = started(RUN2_STAGE2_DONE - 1)
    assert _pve_verify(tmp_path, "dcagent", "dc", "3", RUN2_STAGE2_DONE, answers=answers, cp=forged) is False


def test_a_proxmox_verify_needs_the_bound(tmp_path: Path) -> None:
    for case, kind, stage in (("dcagent", "dc", "3"), ("wg", "workgroup", "2")):
        adapter = _pve_adapter(tmp_path, FakePve(_pve_answers(case)))
        with pytest.raises(TypeError):
            adapter.verify(PVE_SERVER, _pve_cp(case), kind, stage=stage)  # type: ignore[call-arg]
        for bad in (None, True, "1794640620", 1794640620.0):
            with pytest.raises(TypeError):
                adapter.verify(PVE_SERVER, _pve_cp(case), kind, stage=stage, not_before=bad)


def test_a_forged_upid_echoed_by_the_status_is_refused_by_the_upid_guards(tmp_path: Path) -> None:
    """A status answer that echoes the forged UPID, of the right VM and
    type: only the UPID's own node, vmid and type guards can refuse it
    (m1 of the task 7 triage)."""
    cp = _pve_cp("dcagent")
    real = cp["id"]

    def echoed(upid: str) -> dict[tuple[str, str], Any]:
        answers = _pve_answers("dcagent", upid=upid)
        status = [k for k in answers if k[1].endswith("/status")][0]
        answers[status]["data"]["upid"] = upid
        assert answers[status]["data"]["id"] == "731" and answers[status]["data"]["type"] == "qmsnapshot"
        return answers

    assert _pve_verify(tmp_path, "dcagent", "dc", "3", RUN2_STAGE2_DONE, answers=echoed(real), cp=cp) is True  # control
    for upid in (
        real.replace("UPID:Apollo:", "UPID:Other:"),
        real.replace(":qmsnapshot:731:", ":qmsnapshot:732:"),
        real.replace(":qmsnapshot:", ":qmrollback:"),
        real.replace(":qmsnapshot:", ":vzdump:"),
    ):
        assert upid != real
        forged = dict(cp, id=upid)
        assert _pve_verify(tmp_path, "dcagent", "dc", "3", RUN2_STAGE2_DONE, answers=echoed(upid), cp=forged) is False


def test_a_pre_promotion_hyperv_checkpoint_is_never_a_dc_checkpoint(tmp_path: Path) -> None:
    """The fake host's workgroup checkpoint (2026-11-10T22:10:05Z), a
    production one, with every partition backed up after it and the
    genid present: older than stage 2's completion, it is unverified."""
    state = copy.deepcopy(HV_STATE)
    for vm in state["vms"]:
        vm["CheckpointType"] = "ProductionOnly"
    host = FakeHvHost(tmp_path, state)
    ss = checkpoint.ShowbackupRead(_text("repadmin-showbackup-ss.txt"), 0)
    adapter = _hv_adapter(host, showbackup=lambda s: ss)
    old = {"name": "build1-fresh-workgroup", "id": "3f2b1c4d-5e6f-4a8b-9c0d-1e2f3a4b5c6d"}
    created = int(datetime(2026, 11, 10, 22, 10, 5, tzinfo=timezone.utc).timestamp())
    assert adapter.verify(HV_SERVER, old, "dc", stage="3", not_before=created) is True  # control
    assert adapter.verify(HV_SERVER, old, "dc", stage="3", not_before=created + 1) is False
    for stage in ("4", "6", "7"):
        assert adapter.verify(HV_SERVER, old, "dc", stage=stage, not_before=RUN2_STAGE2_DONE) is False
    assert adapter.verify(HV_SERVER, old, "workgroup", stage="2", not_before=HV_NBF) is False


def _hv_listing(created: str) -> tuple[int, str]:
    one = {"name": "newton-dc-1", "id": "6a5b4c3d-2e1f-4a0b-9c8d-7e6f5a4b3c2d", "created": created, "vm": "BUILD1", "checkpoint_type": "ProductionOnly"}
    return 0, _json.dumps([one])


def test_a_hyperv_checkpoint_at_or_after_the_bound_verifies() -> None:
    cp = {"name": "newton-dc-1", "id": "6a5b4c3d-2e1f-4a0b-9c8d-7e6f5a4b3c2d"}
    at = int(datetime(2026, 11, 11, 0, 23, 51, tzinfo=timezone.utc).timestamp())
    adapter = _hv_adapter(lambda argv: _hv_listing("2026-11-11T00:23:51Z"))
    assert adapter.verify(HV_SERVER, cp, "workgroup", stage="2", not_before=at) is True
    assert adapter.verify(HV_SERVER, cp, "workgroup", stage="2", not_before=at + 1) is False


def test_a_hyperv_checkpoint_with_an_unparsable_time_is_unverified() -> None:
    cp = {"name": "newton-dc-1", "id": "6a5b4c3d-2e1f-4a0b-9c8d-7e6f5a4b3c2d"}
    for created in ("2026-13-40T25:61:61Z", "2026-02-30T00:00:00Z"):
        adapter = _hv_adapter(lambda argv, c=created: _hv_listing(c))
        assert adapter.verify(HV_SERVER, cp, "workgroup", stage="2", not_before=HV_NBF) is False


def test_a_hyperv_verify_needs_the_bound() -> None:
    cp = {"name": "newton-dc-1", "id": "6a5b4c3d-2e1f-4a0b-9c8d-7e6f5a4b3c2d"}
    adapter = _hv_adapter(lambda argv: _hv_listing("2026-11-14T07:31:08Z"))
    for kind, stage in (("dc", "3"), ("workgroup", "2")):
        with pytest.raises(TypeError):
            adapter.verify(HV_SERVER, cp, kind, stage=stage)  # type: ignore[call-arg]
        for bad in (None, True, "1794640620", 1794640620.0):
            with pytest.raises(TypeError):
                adapter.verify(HV_SERVER, cp, kind, stage=stage, not_before=bad)
