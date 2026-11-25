"""Stage 4 ends with a DC1 reboot and reads the build login's groups back.

THE MAINTAINER'S DECISION (2026-11-13): after s4-laps removes newton-build from
Enterprise Admins and Schema Admins, the helper records ``rebooting``
and restarts DC1 the way stage 2 does.  After the boot a status request
reads (a) the directory, where newton-build must be in neither Enterprise
Admins (RID 519) nor Schema Admins (RID 518), and (b) the token of the
helper's own S4U key login, which must hold neither SID.  Both must pass
for ``done``.  Either failing stops ``privileged_groups_remain`` and the
check names which.  A read that fails or is malformed stops
``readback_failed``, never passes.

THE FIXTURES ARE MEASURED (MEASURED-1.5 "Stage 4 reboot, 2026-11-13/14"),
on BUILD1 over the newton-build S4U key login, the domain SID masked:
``s4-groups.txt`` is the op's output after the boot,
``s4-s4u-groups-before-boot.txt`` the key login's token after s4-laps and
before the reboot (it still holds 518 and 519),
``s4-s4u-groups-after-boot.txt`` the token after the boot (neither),
``s4-groups-directory-unready.txt`` the op as soon as the key login
answered after the boot, before ADWS served, and
``s4-groups-task-before-boot.txt`` the op in a password task before the
reboot.
"""

from __future__ import annotations

import copy
from typing import Any

import pytest

from newton_mcp.ad.build import plan
from test_build_stages_0_4 import (  # noqa: F401  (server is a fixture)
    BOOT_0,
    BOOT_1,
    EXP,
    PLAN_INPUTS,
    Server,
    _call,
    _fixture,
    _kinds,
    _ok,
    _ops_called,
    _plan,
    _render,
    _restarts,
    _s4_output,
    _seed_before,
    _stage_values,
    _states,
    _stopped,
    server,
)

CP = "cp-4"
GRACE = 900
DOMAIN_SID = "S-1-5-21-1000000001-1000000002-1000000003"


def _lines(name: str) -> list[str]:
    return [line for line in _fixture(name).splitlines() if line]


def _before_boot_token() -> list[str]:
    return _lines("s4-s4u-groups-before-boot.txt")


def _after_boot_token() -> list[str]:
    return _lines("s4-s4u-groups-after-boot.txt")


def _groups_ok() -> dict[str, dict[str, Any]]:
    return {"s4-groups": _ok(_fixture("s4-groups.txt"))}


def _rebooting_stage_4(server: Server) -> dict[str, Any]:
    """Stage 4 run: s4-laps passed, rebooting entry, restart."""
    the_plan = _plan()
    _seed_before(server, the_plan, "4", CP)
    result = _call(server, the_plan, "4", ops={"s4-laps": _ok(_s4_output())}, checkpoint=CP, boot=BOOT_0)
    assert result["answer"]["status"] == "rebooting", result
    return the_plan


def _post_boot(server: Server, the_plan: dict[str, Any], **kw: Any) -> dict[str, Any]:
    kw.setdefault("ops", _groups_ok())
    kw.setdefault("groups", _after_boot_token())
    return _call(server, the_plan, "4", "status", checkpoint=CP, boot=BOOT_1, **kw)


# ---------------------------------------------------------------------------
# the measured bytes
# ---------------------------------------------------------------------------


def test_the_measured_token_holds_ea_and_sa_until_the_reboot_and_not_after() -> None:
    before = "\n".join(_before_boot_token())
    after = "\n".join(_after_boot_token())
    for rid in ("518", "519"):
        assert f'"{DOMAIN_SID}-{rid}"' in before
        assert f'"{DOMAIN_SID}-{rid}"' not in after
    assert f'"{DOMAIN_SID}-512"' in after


def test_the_measured_directory_has_the_build_account_out_of_ea_and_sa() -> None:
    for name in ("s4-groups.txt", "s4-groups-task-before-boot.txt"):
        text = _fixture(name)
        assert f"Enterprise Admins ({DOMAIN_SID}-519) members: Administrator\n" in text
        assert f"Schema Admins ({DOMAIN_SID}-518) members: Administrator\n" in text


def test_the_s4_groups_op_reads_the_directory_by_rid(server: Server) -> None:
    script = _render(server, _stage_values(server), ["s4-groups"])["s4-groups"]
    assert "Get-ADPrincipalGroupMembership -Identity $BuildUser" in script
    assert "foreach ($rid in '519', '518')" in script
    assert "Get-ADGroupMember -Identity $g -Recursive" in script
    assert "$BuildUser = 'newton-build'" in script
    for writer in ("Remove-ADGroupMember", "Add-ADGroupMember", "Set-AD", "Restart-Computer", "shutdown"):
        assert writer not in script


# ---------------------------------------------------------------------------
# the run: s4-laps, then rebooting and the restart
# ---------------------------------------------------------------------------


def test_stage_4_ends_with_a_rebooting_entry_and_a_restart(server: Server) -> None:
    the_plan = _plan()
    _seed_before(server, the_plan, "4", CP)
    result = _call(server, the_plan, "4", ops={"s4-laps": _ok(_s4_output())}, checkpoint=CP)
    assert result["answer"]["status"] == "rebooting", result
    assert result["answer"]["ok"] is True
    assert _ops_called(result) == ["s4-laps"]
    assert _restarts(result) == 1
    assert _states(server, "4") == ["checkpointed", "started", "rebooting"]
    rebooting = [e for e in server.journal() if e["stage"] == "4"][-1]
    assert rebooting["checkpoint"] == CP
    assert rebooting["boot"] == BOOT_0
    assert all(c["ok"] for c in result["answer"]["checks"])


def test_a_refused_stage_4_restart_stops_the_stage(server: Server) -> None:
    the_plan = _plan()
    _seed_before(server, the_plan, "4", CP)
    result = _call(server, the_plan, "4", ops={"s4-laps": _ok(_s4_output())}, checkpoint=CP, restart=False)
    _stopped(server, result, "4", "error")
    assert _states(server, "4") == ["checkpointed", "started", "rebooting", "stopped"]


def test_a_failed_s4_laps_read_back_stops_with_no_restart(server: Server) -> None:
    the_plan = _plan()
    _seed_before(server, the_plan, "4", CP)
    output = _s4_output().replace("  Enterprise Admins members: Administrator\n",
                                  "  Enterprise Admins members: Administrator, newton-build\n")
    assert output != _s4_output()
    result = _call(server, the_plan, "4", ops={"s4-laps": _ok(output)}, checkpoint=CP)
    _stopped(server, result, "4", "readback_failed")
    assert _restarts(result) == 0


def test_a_status_before_the_boot_advances_runs_nothing(server: Server) -> None:
    the_plan = _rebooting_stage_4(server)
    result = _call(server, the_plan, "4", "status", checkpoint=CP, boot=BOOT_0)
    assert result["answer"]["status"] == "rebooting"
    assert result["calls"] == []
    assert _states(server, "4")[-1] == "rebooting"


# ---------------------------------------------------------------------------
# after the boot: the directory and the S4U token
# ---------------------------------------------------------------------------


def test_after_the_boot_both_reads_pass_and_the_stage_is_done(server: Server) -> None:
    the_plan = _rebooting_stage_4(server)
    result = _post_boot(server, the_plan)
    assert result["answer"]["status"] == "done", result
    assert result["answer"]["ok"] is True
    assert [c["kind"] for c in result["calls"] if c["kind"] in ("wait", "op", "restart")] == ["wait", "op"]
    op = [c for c in result["calls"] if c["kind"] == "op"][0]
    # The read runs in the helper's own session: the S4U key login.
    assert op["op"] == "s4-groups" and op["task"] is False
    checks = {c["name"]: c for c in result["answer"]["checks"]}
    assert checks["directory_groups"]["ok"] is True
    assert checks["s4u_token_groups"]["ok"] is True
    assert _states(server, "4") == ["checkpointed", "started", "rebooting", "done"]


def test_the_token_still_holding_ea_and_sa_stops_privileged_groups_remain(server: Server) -> None:
    """The measured token of the key login before the reboot."""
    the_plan = _rebooting_stage_4(server)
    result = _post_boot(server, the_plan, groups=_before_boot_token())
    _stopped(server, result, "4", "privileged_groups_remain")
    checks = {c["name"]: c for c in result["answer"]["checks"]}
    assert checks["directory_groups"]["ok"] is True
    assert checks["s4u_token_groups"]["ok"] is False
    assert "519" in checks["s4u_token_groups"]["detail"] and "518" in checks["s4u_token_groups"]["detail"]
    assert "done" not in _states(server, "4")


@pytest.mark.parametrize("rid", ["518", "519"])
def test_the_token_holding_one_of_them_stops(server: Server, rid: str) -> None:
    the_plan = _rebooting_stage_4(server)
    token = [g for g in _before_boot_token() if not g.split('","')[2].endswith("-" + ("519" if rid == "518" else "518"))]
    assert len(token) == len(_before_boot_token()) - 1
    result = _post_boot(server, the_plan, groups=token)
    _stopped(server, result, "4", "privileged_groups_remain")
    detail = {c["name"]: c for c in result["answer"]["checks"]}["s4u_token_groups"]["detail"]
    assert rid in detail


def test_a_deny_only_ea_sid_in_the_token_still_stops(server: Server) -> None:
    """Any 518 or 519 SID in the token counts, enabled or not."""
    the_plan = _rebooting_stage_4(server)
    token = _after_boot_token() + [f'"NBUILD\\Enterprise Admins","Group","{DOMAIN_SID}-519","Group used for deny only"']
    result = _post_boot(server, the_plan, groups=token)
    _stopped(server, result, "4", "privileged_groups_remain")


@pytest.mark.parametrize(
    ("old", "new"),
    [
        (
            "  Enterprise Admins (S-1-5-21-1000000001-1000000002-1000000003-519) members: Administrator\n",
            "  Enterprise Admins (S-1-5-21-1000000001-1000000002-1000000003-519) members: Administrator, newton-build\n",
        ),
        (
            "  Schema Admins (S-1-5-21-1000000001-1000000002-1000000003-518) members: Administrator\n",
            "  Schema Admins (S-1-5-21-1000000001-1000000002-1000000003-518) members: newton-build\n",
        ),
        (
            "Domain Users (S-1-5-21-1000000001-1000000002-1000000003-513)\n",
            "Domain Users (S-1-5-21-1000000001-1000000002-1000000003-513), "
            "Schema Admins (S-1-5-21-1000000001-1000000002-1000000003-518)\n",
        ),
        (
            "Domain Users (S-1-5-21-1000000001-1000000002-1000000003-513)\n",
            "Domain Users (S-1-5-21-1000000001-1000000002-1000000003-513), "
            "Enterprise Admins (S-1-5-21-1000000001-1000000002-1000000003-519)\n",
        ),
        (
            "  Schema Admins (S-1-5-21-1000000001-1000000002-1000000003-518) members: Administrator\n",
            "  Schema Admins (S-1-5-21-1000000001-1000000002-1000000003-518) members: Administrator, NEWTON-BUILD\n",
        ),
    ],
)
def test_the_directory_still_holding_the_account_stops_privileged_groups_remain(
    server: Server, old: str, new: str
) -> None:
    the_plan = _rebooting_stage_4(server)
    output = _fixture("s4-groups.txt").replace(old, new)
    assert output != _fixture("s4-groups.txt")
    result = _post_boot(server, the_plan, ops={"s4-groups": _ok(output)})
    _stopped(server, result, "4", "privileged_groups_remain")
    checks = {c["name"]: c for c in result["answer"]["checks"]}
    assert checks["directory_groups"]["ok"] is False
    assert checks["s4u_token_groups"]["ok"] is True


def _drop_line(prefix: str) -> str:
    return "".join(l for l in _fixture("s4-groups.txt").splitlines(keepends=True) if not l.startswith(prefix))


@pytest.mark.parametrize(
    "output",
    [
        pytest.param(_drop_line("Get-ADPrincipalGroupMembership: "), id="no-membership-line"),
        pytest.param(_drop_line("  Enterprise Admins ("), id="no-ea-line"),
        pytest.param(_drop_line("  Schema Admins ("), id="no-sa-line"),
        pytest.param(_drop_line("domain: "), id="no-domain-line"),
        pytest.param(
            _fixture("s4-groups.txt").replace("Get-ADPrincipalGroupMembership: Administrators", "Get-ADPrincipalGroupMembership: "),
            id="membership-item-without-name",
        ),
        pytest.param(
            _fixture("s4-groups.txt").replace(
                "Get-ADPrincipalGroupMembership: Administrators (S-1-5-32-544), Domain Admins (S-1-5-21-1000000001-1000000002-1000000003-512), Domain Users (S-1-5-21-1000000001-1000000002-1000000003-513)",
                "Get-ADPrincipalGroupMembership: ",
            ),
            id="membership-empty",
        ),
        pytest.param(
            _fixture("s4-groups.txt").replace("domain: build.newton.test", "domain: other.newton.test"),
            id="another-domain",
        ),
        pytest.param(
            _fixture("s4-groups.txt").replace(
                "  Schema Admins (S-1-5-21-1000000001-1000000002-1000000003-518)",
                "  Schema Admins (S-1-5-21-1000000001-1000000002-1000000009-518)",
            ),
            id="sa-of-another-domain-sid",
        ),
        pytest.param(_fixture("s4-groups.txt") + "  Schema Admins (S-1-5-21-1000000001-1000000002-1000000003-518) members: Administrator\n",
                     id="sa-line-twice"),
        pytest.param("", id="empty"),
    ],
)
def test_a_malformed_directory_read_stops_readback_failed(server: Server, output: str) -> None:
    the_plan = _rebooting_stage_4(server)
    assert output != _fixture("s4-groups.txt")
    result = _post_boot(server, the_plan, ops={"s4-groups": _ok(output)})
    _stopped(server, result, "4", "readback_failed")
    checks = {c["name"]: c for c in result["answer"]["checks"]}
    assert checks["directory_groups"]["ok"] is False


def test_a_failed_directory_read_stops_readback_failed(server: Server) -> None:
    """The measured op as soon as the key login answered, before ADWS
    served: it failed, so the stage stops; it never passes."""
    the_plan = _rebooting_stage_4(server)
    result = _post_boot(server, the_plan, ops={"s4-groups": {"result": 1, "output": _fixture("s4-groups-directory-unready.txt")}})
    _stopped(server, result, "4", "readback_failed")


@pytest.mark.parametrize(
    "token",
    [
        pytest.param([], id="no-lines"),
        pytest.param(["garbage"], id="not-csv"),
        pytest.param(["ERROR: Access is denied."], id="whoami-error"),
        pytest.param([l for l in _lines("s4-s4u-groups-after-boot.txt") if "S-1-5-32-544" not in l], id="no-administrators"),
        pytest.param(_lines("s4-s4u-groups-after-boot.txt") + ['"half a line'], id="one-bad-line"),
    ],
)
def test_a_malformed_token_read_stops_readback_failed(server: Server, token: list[str]) -> None:
    the_plan = _rebooting_stage_4(server)
    result = _post_boot(server, the_plan, groups=token)
    _stopped(server, result, "4", "readback_failed")
    checks = {c["name"]: c for c in result["answer"]["checks"]}
    assert checks["s4u_token_groups"]["ok"] is False


def test_the_directory_never_answering_after_the_boot_stops(server: Server) -> None:
    the_plan = _rebooting_stage_4(server)
    result = _post_boot(server, the_plan, directory=False)
    _stopped(server, result, "4", "directory_unready")
    assert _ops_called(result) == []


def test_the_post_boot_read_never_restarts(server: Server) -> None:
    the_plan = _rebooting_stage_4(server)
    result = _post_boot(server, the_plan, groups=_before_boot_token())
    assert _restarts(result) == 0


# ---------------------------------------------------------------------------
# the rebooting rules: EXP plus the grace, the plan
# ---------------------------------------------------------------------------


def test_the_post_boot_read_is_done_inside_the_grace(server: Server) -> None:
    the_plan = _rebooting_stage_4(server)
    result = _post_boot(server, the_plan, now=EXP + GRACE // 2)
    assert result["answer"]["status"] == "done", result


def test_the_post_boot_read_past_the_grace_stops_grace_passed(server: Server) -> None:
    the_plan = _rebooting_stage_4(server)
    result = _post_boot(server, the_plan, now=EXP + GRACE + 1)
    answer = result["answer"]
    assert (answer["status"], answer["code"]) == ("refused", "expired"), result
    assert _ops_called(result) == []
    last = [e for e in server.journal() if e["stage"] == "4"][-1]
    assert (last["state"], last["reason"]) == ("stopped", "grace_passed")


def test_a_changed_plan_byte_does_not_complete_the_stage(server: Server) -> None:
    the_plan = _rebooting_stage_4(server)
    before = server.journal()
    inputs = copy.deepcopy(PLAN_INPUTS)
    inputs["domain"]["site"] = "Other-Site"
    other = _plan(inputs)
    result = _call(server, other, "4", "status", checkpoint=CP, boot=BOOT_1, ops=_groups_ok(), groups=_after_boot_token())
    assert result["answer"]["status"] == "refused", result
    assert _ops_called(result) == []
    assert server.journal() == before


# ---------------------------------------------------------------------------
# the record path: a session dropped while s4-laps ran
# ---------------------------------------------------------------------------


def _dropped_stage_4(server: Server) -> dict[str, Any]:
    the_plan = _plan()
    _seed_before(server, the_plan, "4", CP)
    dropped = _call(server, the_plan, "4", ops={"s4-laps": {"drop": True, "result": 0, "output": ""}}, checkpoint=CP)
    assert dropped.get("dropped") is True, dropped
    return the_plan


def test_a_dropped_stage_4_is_recorded_rebooting_and_restarts(server: Server) -> None:
    the_plan = _dropped_stage_4(server)
    result = _call(server, the_plan, "4", "status", checkpoint=CP, results={"s4-laps": _ok(_s4_output())})
    assert result["answer"]["status"] == "rebooting", result
    assert _states(server, "4") == ["checkpointed", "started", "rebooting"]
    assert _restarts(result) == 1
    assert _ops_called(result) == []
    # Then the boot and the read.
    done = _post_boot(server, the_plan)
    assert done["answer"]["status"] == "done", done


def test_a_dropped_stage_4_recorded_inside_the_grace_restarts(server: Server) -> None:
    the_plan = _dropped_stage_4(server)
    result = _call(server, the_plan, "4", "status", checkpoint=CP, now=EXP + 300,
                   results={"s4-laps": _ok(_s4_output())})
    assert result["answer"]["status"] == "rebooting", result
    assert _restarts(result) == 1


def test_a_dropped_stage_4_recorded_past_the_grace_stops_with_no_restart(server: Server) -> None:
    the_plan = _dropped_stage_4(server)
    result = _call(server, the_plan, "4", "status", checkpoint=CP, now=EXP + GRACE + 60,
                   results={"s4-laps": _ok(_s4_output())})
    _stopped(server, result, "4", "grace_passed")
    assert _restarts(result) == 0
    assert _kinds(result, "task-removed") == ["task-removed"]
