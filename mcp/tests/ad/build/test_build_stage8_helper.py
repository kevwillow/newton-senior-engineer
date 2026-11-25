"""Stage 8 of the helper: the 1.4 newton-ops setup and the 1.3 newton-audit
setup on DC1 (the maintainer's decision R1, 2026-11-15, and his rulings on DESIGN-1.5
open points 34 and 37, 2026-11-16).

The bootstrap installs each setup generator's build template in the
helper's install root, and the write helper beside them (the maintainer's decision of
2026-11-19 on the stage 8 transport, DESIGN-1.5 open point 78: nothing
large goes over stdin); the helper fills the generators' placeholders from
the plan bytes and the installed write helper's bytes (their sha256 must
be the plan's), runs each filled setup in the password task, then
registers one SYSTEM task that restarts sshd after its answer has left.  A
later status finds that task's result file and reads stage 8 back.

The read-back's lines and the restart's are constructed (the apollo lab
could not run on 2026-11-16; DESIGN-1.5, the task 8 open points): they are
the lines the rendered ops print, fed to the parsers here.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from newton_mcp.approve import approval_fingerprint, approval_token
from newton_mcp.ad import setupgen, setupgen_write
from newton_mcp.ad.build import plan
from ops_fixture import OPS  # type: ignore[import-not-found]
from test_build_stages_0_4 import (  # type: ignore[import-not-found]
    BASE,
    DRIVER,
    EXP,
    KEY_HEX,
    NBF,
    PLAN_INPUTS,
    RUN,
    Server,
    _ok,
    _ops_called,
    _pwsh,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "stage8"

WRITE_HELPER = setupgen_write.WRITE_HELPER_PATH.read_bytes()

#: The fakes stage 8 needs beside the driver's: the filled setups the
#: helper writes, and the state of the sshd restart task.
STAGE8_FAKES = r"""
function Write-NewtonSetupScript {
    param([string]$Path, [string]$Text)
    [void]$script:DriverCalls.Add([ordered]@{ kind = 'setup-script'; path = $Path; text = $Text })
}

function Test-NewtonSshdRestartRunning {
    return (@($script:DriverIn.fake.running) -contains 's8-sshd')
}

"""

#: A mode of the driver that reads the values of stage 8 out of plan bytes.
OPS_VALUES_MODE = r"""    'ops-values' {
        try {
            $plan = ConvertFrom-NewtonPlanBytes ([Convert]::FromBase64String([string]$script:DriverIn.plan))
            $result.values = Get-NewtonOpsValues -Plan $plan -Role ([string]$script:DriverIn.role)
        } catch {
            $result.error = Get-NewtonRefusalCode $_
        }
    }
    'secret' {"""

DRIVER8 = DRIVER.replace("$result = [ordered]@{}\nswitch", STAGE8_FAKES + "$result = [ordered]@{}\nswitch", 1)
DRIVER8 = DRIVER8.replace("    'secret' {", OPS_VALUES_MODE, 1)
assert DRIVER8.count("'ops-values'") == 1 and STAGE8_FAKES in DRIVER8


class Server8(Server):
    """BUILD1's install root with the stage 8 templates the bootstrap
    installs there."""

    def __init__(self, root: Path) -> None:
        super().__init__(root)
        self.driver.write_text(DRIVER8, encoding="utf-8")
        (root / "s8-audit.tmpl.ps1").write_bytes(setupgen.windows_template(build=True).encode("utf-8"))
        (root / "s8-ops.tmpl.ps1").write_bytes(setupgen_write.windows_write_template(build=True).encode("utf-8"))
        (root / "s8-write.ps1").write_bytes(WRITE_HELPER)


@pytest.fixture
def server(tmp_path: Path) -> Server8:
    return Server8(tmp_path / "install")


def _plan() -> dict[str, Any]:
    return plan.plan_build(copy.deepcopy(PLAN_INPUTS))


def _seed_to_8(server: Server8, the_plan: dict[str, Any]) -> None:
    digest = plan.digest(the_plan)
    records: list[dict[str, Any]] = []
    for stage in ["0", "1", "2", "3", "4", "5", "6"]:
        records.append({"stage": stage, "state": "started", "digest": digest})
        records.append({"stage": stage, "state": "done", "digest": digest})
    server.seed(records)


def _request(the_plan: dict[str, Any], stage: str = "8", action: str = "run", *, helper: bytes | None = None,
             extra: dict[str, Any] | None = None) -> str:
    request: dict[str, Any] = {
        "run": RUN,
        "plan": base64.b64encode(plan.canonical_bytes(the_plan)).decode("ascii"),
        "stage": stage,
        "action": action,
        "token": approval_token(KEY_HEX, plan.digest(the_plan), NBF, EXP),
        "nbf": NBF,
        "exp": EXP,
    }
    if helper is not None:
        request["write_helper"] = base64.b64encode(helper).decode("ascii")
    request.update(extra or {})
    return json.dumps(request)


def _drive(server: Server8, request: str, *, ops: dict[str, Any] | None = None, results: dict[str, Any] | None = None,
           running: list[str] | None = None, now: int = BASE) -> dict[str, Any]:
    payload = {
        "mode": "request",
        "request": request,
        "fake": {"ops": ops or {}, "groups": [], "directory": True, "restart": True, "results": results or {},
                 "running": running or []},
    }
    return server.drive(payload, now=now)


# --------------------------------------------------------------------------
# the outputs the fakes answer
# --------------------------------------------------------------------------

DOMAIN = "build.newton.test"
DEVICE = "build1"
HOST = "192.0.2.41"
OUS = ["OU=IT,DC=build,DC=newton,DC=test"]


def _filled(op: str) -> str:
    if op == "s8-audit":
        return setupgen.fill_windows(setupgen.windows_template(build=True), domain=DOMAIN, device=DEVICE, host=HOST,
                                     pubkey=OPS["audit_public_key"])
    return setupgen_write.fill_windows_write(setupgen_write.windows_write_template(build=True), domain=DOMAIN,
                                             device=DEVICE, host=HOST, ous=OUS, pubkey=OPS["public_key"],
                                             helper=WRITE_HELPER)


def _script_sha(op: str) -> str:
    return hashlib.sha256(b"\xef\xbb\xbf" + _filled(op).encode("utf-8")).hexdigest()


SETUP_PATHS = {"s8-audit": "C:\\NewtonBuild\\ops\\s8-audit-setup.ps1", "s8-ops": "C:\\NewtonBuild\\ops\\s8-ops-setup.ps1"}

AUDIT_STEPS = ["Step 1: the newton-audit account", "Step 2: the collector files", "Step 3: the access control list",
               "Step 4: the authorized key", "Step 5: the sshd configuration", "Step 7: the inventory entry"]
OPS_STEPS = ["Step 0: the pre-checks", "Step 1: the newton-ops account", "Step 2: the delegation",
             "Step 3: the approval key", "Step 4: the files", "Step 5: the login", "Step 6: the SeBatchLogonRight",
             "Step 7: the inventory entry"]


def _key_sha(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def _setup_out(op: str) -> str:
    lines = ["task identity: nbuild\\newton-build | auth Kerberos", "task start 2026-11-16T12:00:00.0000000Z",
             f"setup script: {SETUP_PATHS[op]}, sha256 {_script_sha(op)}"]
    if op == "s8-audit":
        lines += AUDIT_STEPS[:-1] + ["sha256 collector.ps1 00", AUDIT_STEPS[-1],
                                    f"The installed public key (sha256): {_key_sha(OPS['audit_public_key'])}"]
    else:
        lines += OPS_STEPS[:3]
        lines += [OPS_STEPS[3], f"The approval key is installed. Its fingerprint is {approval_fingerprint(KEY_HEX)}"]
        lines += [OPS_STEPS[4], f"sha256 write.ps1 {OPS['write_helper_sha256']}"] + OPS_STEPS[5:]
        lines += [f"The installed public key (sha256): {_key_sha(OPS['public_key'])}"]
    lines += ["setup exit 0", "task end 2026-11-16T12:00:20.0000000Z"]
    return "\n".join(lines) + "\n"


RESTART_OUT = (
    "task identity: nbuild\\newton-build | NTLM\n"
    "task start 2026-11-16T12:00:21.0000000Z\n"
    "restart script: C:\\ProgramData\\Newton\\ad-build-sshd-restart.ps1, bytes 2010\n"
    "registered NewtonBuild-sshd-restart as SYSTEM LogonType ServiceAccount\n"
    "state Running\n"
    "task end 2026-11-16T12:00:23.0000000Z\n"
)

SSHD_OUT = "identity nt authority\\system\r\nsshd -t exit 0\r\nsshd restarted: Running | pid 3012 -> 4410\r\n"


def _read_out() -> str:
    text = (FIXTURES / "s8-read-constructed.txt").read_text(encoding="ascii")
    return text.replace("@@WRITE_SHA@@", OPS["write_helper_sha256"])


def _run_ops() -> dict[str, Any]:
    return {"s8-audit": _ok(_setup_out("s8-audit")), "s8-ops": _ok(_setup_out("s8-ops")), "s8-restart": _ok(RESTART_OUT)}


def _states(server: Server8) -> list[tuple[str, str]]:
    return [(e["state"], e.get("phase", "")) for e in server.journal() if e["stage"] == "8"]


def _to_restart(server: Server8) -> dict[str, Any]:
    the_plan = _plan()
    _seed_to_8(server, the_plan)
    result = _drive(server, _request(the_plan), ops=_run_ops())
    assert result["answer"]["status"] == "started", result
    return the_plan


# --------------------------------------------------------------------------
# the run
# --------------------------------------------------------------------------


def test_the_helper_fills_each_template_as_the_generator_does(server: Server8) -> None:
    the_plan = _plan()
    _seed_to_8(server, the_plan)
    result = _drive(server, _request(the_plan), ops=_run_ops())
    scripts = {c["path"]: c["text"] for c in result["calls"] if c["kind"] == "setup-script"}
    assert scripts == {SETUP_PATHS["s8-audit"]: _filled("s8-audit"), SETUP_PATHS["s8-ops"]: _filled("s8-ops")}


def test_stage_8_runs_both_setups_in_the_password_task_then_registers_the_restart(server: Server8) -> None:
    the_plan = _plan()
    _seed_to_8(server, the_plan)
    result = _drive(server, _request(the_plan), ops=_run_ops())
    assert result["answer"]["ok"] is True, result
    assert result["answer"]["status"] == "started"
    assert _ops_called(result) == ["s8-audit", "s8-ops", "s8-restart"]
    tasks = {c["op"]: c["task"] for c in result["calls"] if c["kind"] == "op"}
    assert tasks == {"s8-audit": True, "s8-ops": True, "s8-restart": False}
    assert _states(server) == [("started", "s8_setup"), ("started", "s8_restart")]
    # the setups are written before their op runs, and neither is the
    # owner's script: no prompt, no restart of its own
    kinds = [c["kind"] for c in result["calls"] if c["kind"] in ("setup-script", "op")]
    assert kinds == ["setup-script", "op", "setup-script", "op", "op"]
    for call in result["calls"]:
        if call["kind"] == "setup-script":
            assert "Read-Host" not in call["text"]
            assert "Restart-Service" not in call["text"]


def test_the_restart_script_restarts_sshd_once_after_its_wait(server: Server8) -> None:
    the_plan = _plan()
    _seed_to_8(server, the_plan)
    result = _drive(server, _request(the_plan), ops=_run_ops())
    script = next(c["script"] for c in result["calls"] if c["kind"] == "op" and c["op"] == "s8-restart")
    encoded = next(line for line in script.splitlines() if line.startswith("$RestartB64 = "))
    text = base64.b64decode(encoded.split("'")[1]).decode("utf-8")
    assert text.index("Start-Sleep -Seconds $Delay") < text.index("& $sshd -t") < text.index("Restart-Service -Name sshd")
    assert text.count("Restart-Service") == 1
    assert "$ResultFile = 'C:\\NewtonBuild\\out\\s8-sshd.rc'" in text
    assert "$Delay = 10" in text


def test_an_installed_write_helper_that_is_not_the_plans_is_refused_before_anything(server: Server8) -> None:
    """The maintainer's decision of 2026-11-19: the bootstrap installed the write helper;
    a file whose sha256 is not the plan's stops the run before any op, any
    setup script or any journal entry."""
    (server.root / "s8-write.ps1").write_bytes(WRITE_HELPER + b"\n")
    the_plan = _plan()
    _seed_to_8(server, the_plan)
    result = _drive(server, _request(the_plan), ops=_run_ops())
    assert (result["answer"]["ok"], result["answer"]["code"]) == (False, "write_helper_mismatch"), result
    assert "run the bootstrap of the server again" in result["error"], result
    assert _ops_called(result) == []
    assert not [c for c in result["calls"] if c["kind"] == "setup-script"]
    assert _states(server) == []


def test_a_missing_installed_write_helper_is_refused_before_anything(server: Server8) -> None:
    (server.root / "s8-write.ps1").unlink()
    the_plan = _plan()
    _seed_to_8(server, the_plan)
    result = _drive(server, _request(the_plan), ops=_run_ops())
    assert (result["answer"]["ok"], result["answer"]["code"]) == (False, "write_helper_missing"), result
    assert "run the bootstrap of the server again" in result["error"], result
    assert _ops_called(result) == []
    assert not [c for c in result["calls"] if c["kind"] == "setup-script"]
    assert _states(server) == []


@pytest.mark.parametrize("case", ["run", "status", "other-stage"])
def test_no_request_carries_the_write_helper(server: Server8, case: str) -> None:
    """The stage 8 run no longer carries the write helper (measured on
    BUILD1, 2026-11-18: PowerShell 5.1 under OpenSSH hangs reading stdin
    past about 70-80 KB); a request that names the field is refused
    ``schema``."""
    the_plan = _plan()
    _seed_to_8(server, the_plan)
    field = {"write_helper": base64.b64encode(WRITE_HELPER).decode("ascii")}
    if case == "run":
        request = _request(the_plan, extra=field)
    elif case == "status":
        request = _request(the_plan, action="status", extra=field)
    else:
        request = _request(the_plan, stage="6", extra=field)
    result = _drive(server, request, ops=_run_ops())
    assert (result["answer"]["ok"], result["answer"]["code"]) == (False, "schema"), result
    assert _ops_called(result) == []
    assert _states(server) == []


def test_a_missing_template_is_refused_before_anything(server: Server8) -> None:
    (server.root / "s8-ops.tmpl.ps1").unlink()
    the_plan = _plan()
    _seed_to_8(server, the_plan)
    result = _drive(server, _request(the_plan), ops=_run_ops())
    assert (result["answer"]["ok"], result["answer"]["code"]) == (False, "schema"), result
    assert "the bootstrap installed no stage 8 template s8-ops.tmpl.ps1" in result["error"], result
    assert _ops_called(result) == []
    assert _states(server) == []


def test_a_template_with_a_placeholder_the_plan_does_not_fill_is_refused(server: Server8) -> None:
    path = server.root / "s8-audit.tmpl.ps1"
    path.write_bytes(path.read_bytes() + b"# @@SOMETHING_ELSE@@\n")
    the_plan = _plan()
    _seed_to_8(server, the_plan)
    result = _drive(server, _request(the_plan), ops=_run_ops())
    assert (result["answer"]["ok"], result["answer"]["code"]) == (False, "schema"), result
    assert _ops_called(result) == []


@pytest.mark.parametrize("op", ["s8-audit", "s8-ops", "s8-read", "s8-sshd"])
def test_a_stage_8_task_still_running_refuses_the_run(server: Server8, op: str) -> None:
    the_plan = _plan()
    _seed_to_8(server, the_plan)
    result = _drive(server, _request(the_plan), ops=_run_ops(), running=[op])
    assert (result["answer"]["ok"], result["answer"]["code"]) == (False, "out_of_order"), result
    assert _ops_called(result) == []
    assert _states(server) == []


@pytest.mark.parametrize(
    "op, drop",
    [
        ("s8-audit", "Step 4: the authorized key\n"),
        ("s8-audit", "Step 7: the inventory entry\n"),
        ("s8-ops", "Step 0: the pre-checks\n"),
        ("s8-ops", "Step 6: the SeBatchLogonRight\n"),
        ("s8-ops", "Step 7: the inventory entry\n"),
    ],
)
def test_a_setup_that_did_not_print_every_step_stops_op_failed(server: Server8, op: str, drop: str) -> None:
    the_plan = _plan()
    _seed_to_8(server, the_plan)
    ops = _run_ops()
    ops[op] = _ok(_setup_out(op).replace(drop, ""))
    result = _drive(server, _request(the_plan), ops=ops)
    assert (result["answer"]["status"], result["answer"]["code"]) == ("stopped", "op_failed"), result
    assert "s8-restart" not in _ops_called(result)
    assert _states(server) == [("started", "s8_setup"), ("stopped", "s8_setup")]


def test_steps_out_of_order_stop_op_failed(server: Server8) -> None:
    the_plan = _plan()
    _seed_to_8(server, the_plan)
    ops = _run_ops()
    out = _setup_out("s8-ops").replace("Step 1: the newton-ops account\n", "").replace(
        "Step 2: the delegation\n", "Step 2: the delegation\nStep 1: the newton-ops account\n")
    ops["s8-ops"] = _ok(out)
    result = _drive(server, _request(the_plan), ops=ops)
    assert result["answer"]["code"] == "op_failed", result


@pytest.mark.parametrize(
    "op, old, new",
    [
        ("s8-audit", "s8-audit-setup.ps1, sha256 ", "s8-audit-setup.ps1, sha256 00"),
        ("s8-audit", "The installed public key (sha256): ", "The installed public key (sha256): 00"),
        ("s8-ops", "The installed public key (sha256): ", "The installed public key (sha256): 00"),
        ("s8-ops", "sha256 write.ps1 ", "sha256 write.ps1 00"),
        ("s8-ops", "Its fingerprint is ", "Its fingerprint is 00"),
    ],
    ids=["audit-script", "audit-key", "ops-key", "write-helper", "fingerprint"],
)
def test_a_setup_line_that_is_not_the_plans_stops_op_failed(server: Server8, op: str, old: str, new: str) -> None:
    the_plan = _plan()
    _seed_to_8(server, the_plan)
    ops = _run_ops()
    ops[op] = _ok(_setup_out(op).replace(old, new))
    result = _drive(server, _request(the_plan), ops=ops)
    assert (result["answer"]["status"], result["answer"]["code"]) == ("stopped", "op_failed"), result
    assert "s8-restart" not in _ops_called(result)


def test_a_setup_that_failed_stops_before_the_next(server: Server8) -> None:
    the_plan = _plan()
    _seed_to_8(server, the_plan)
    ops = _run_ops()
    ops["s8-audit"] = {"result": 1, "output": "FAIL: System.Exception: the newton-audit account is missing\n"}
    result = _drive(server, _request(the_plan), ops=ops)
    assert result["answer"]["code"] == "op_failed", result
    assert _ops_called(result) == ["s8-audit"]


def test_a_setup_still_running_at_its_wait_stops_op_failed(server: Server8) -> None:
    the_plan = _plan()
    _seed_to_8(server, the_plan)
    ops = _run_ops()
    ops["s8-ops"] = {"result": -1, "output": "", "outcome": "running"}
    result = _drive(server, _request(the_plan), ops=ops)
    assert (result["answer"]["status"], result["answer"]["code"]) == ("stopped", "op_failed"), result
    assert _ops_called(result) == ["s8-audit", "s8-ops"]


@pytest.mark.parametrize("old, new", [("as SYSTEM LogonType ServiceAccount", "as newton-build LogonType Password"),
                                      ("state Running", "state Disabled")])
def test_a_restart_task_that_is_not_a_system_task_stops(server: Server8, old: str, new: str) -> None:
    the_plan = _plan()
    _seed_to_8(server, the_plan)
    ops = _run_ops()
    ops["s8-restart"] = _ok(RESTART_OUT.replace(old, new))
    result = _drive(server, _request(the_plan), ops=ops)
    assert (result["answer"]["status"], result["answer"]["code"]) == ("stopped", "op_failed"), result


def test_a_second_run_of_a_stage_8_in_flight_is_refused(server: Server8) -> None:
    the_plan = _to_restart(server)
    result = _drive(server, _request(the_plan), ops=_run_ops())
    assert (result["answer"]["ok"], result["answer"]["code"]) == (False, "out_of_order"), result
    assert _ops_called(result) == []


# --------------------------------------------------------------------------
# the status: the restart, then the read-back
# --------------------------------------------------------------------------


def test_the_status_waits_for_the_restart(server: Server8) -> None:
    the_plan = _to_restart(server)
    result = _drive(server, _request(the_plan, action="status", helper=None), ops={"s8-read": _ok(_read_out())})
    assert (result["answer"]["ok"], result["answer"]["status"]) == (True, "started"), result
    assert _ops_called(result) == []
    assert _states(server) == [("started", "s8_setup"), ("started", "s8_restart")]


def test_the_status_after_the_restart_reads_stage_8_back_and_ends_done(server: Server8) -> None:
    the_plan = _to_restart(server)
    result = _drive(server, _request(the_plan, action="status", helper=None), ops={"s8-read": _ok(_read_out())},
                    results={"s8-sshd": {"result": 0, "output": SSHD_OUT}})
    assert (result["answer"]["ok"], result["answer"]["status"]) == (True, "done"), result
    assert _ops_called(result) == ["s8-read"]
    assert [c["task"] for c in result["calls"] if c["kind"] == "op"] == [True]
    names = [c["name"] for c in result["answer"]["checks"]]
    assert names == ["sshd_restart", "ops_login", "audit_login", "write_helper", "approval_key", "sshd_answers",
                     "audit_unprivileged", "ops_delegation"]
    assert _states(server)[-1] == ("done", "s8_restart")


@pytest.mark.parametrize("rc", [1, 2, 3])
def test_a_restart_that_failed_stops_op_failed_with_no_read(server: Server8, rc: int) -> None:
    the_plan = _to_restart(server)
    result = _drive(server, _request(the_plan, action="status", helper=None), ops={"s8-read": _ok(_read_out())},
                    results={"s8-sshd": {"result": rc, "output": "sshd -t exit 1\r\n"}})
    assert (result["answer"]["status"], result["answer"]["code"]) == ("stopped", "op_failed"), result
    assert _ops_called(result) == []


def test_a_restart_with_no_result_past_its_wait_stops(server: Server8) -> None:
    the_plan = _to_restart(server)
    result = _drive(server, _request(the_plan, action="status", helper=None), ops={"s8-read": _ok(_read_out())},
                    now=BASE + 901)
    assert (result["answer"]["status"], result["answer"]["code"]) == ("stopped", "op_failed"), result
    assert _ops_called(result) == []


@pytest.mark.parametrize(
    "old, new, check",
    [
        ("sshd match newton-ops: 1", "sshd match newton-ops: 0", "ops_login"),
        ("sshd match newton-ops: 1", "sshd match newton-ops: 2", "ops_login"),
        ("ops keys: restrict ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAB", "ops keys: restrict ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAC", "ops_login"),
        ("sshd match newton-audit: 1", "sshd match newton-audit: 0", "audit_login"),
        ("audit keys: restrict ", "audit keys: ", "audit_login"),
        ("write helper sha256: ", "write helper sha256: 00", "write_helper"),
        ("approval key is the build key: True", "approval key is the build key: False", "approval_key"),
        ("sshd service: Running", "sshd service: Stopped", "sshd_answers"),
        ("sshd banner: SSH-2.0-OpenSSH_for_Windows_9.5", "sshd banner: ", "sshd_answers"),
        ("-513,S-1-5-32-585", "-513,S-1-5-21-1000000001-1000000002-1000000003-512", "audit_unprivileged"),
        ("-513,S-1-5-32-585", "-513,S-1-5-32-544", "audit_unprivileged"),
        ("audit token groups: S-1-5-21-1000000001-1000000002-1000000003-513,S-1-5-32-585", "audit token groups: ", "audit_unprivileged"),
        ("ops explicit aces: DC=build,DC=newton,DC=test | 1\n",
         "ops explicit aces: DC=build,DC=newton,DC=test | 1\nops explicit aces: OU=Domain Controllers,DC=build,DC=newton,DC=test | 2\n",
         "ops_delegation"),
        ("ops explicit aces: OU=IT,DC=build,DC=newton,DC=test | 13\n", "", "ops_delegation"),
        ("ops ace scan: 243 objects\n", "", "ops_delegation"),
        # the same count, one object not the plan's: the set is read, not
        # only its size
        ("ops explicit aces: OU=IT,DC=build,DC=newton,DC=test | 13\n",
         "ops explicit aces: OU=Domain Controllers,DC=build,DC=newton,DC=test | 13\n", "ops_delegation"),
    ],
    ids=["ops-no-block", "ops-two-blocks", "ops-other-key", "audit-no-block", "audit-no-restrict", "write-helper",
         "k-not-shared", "sshd-stopped", "no-banner", "audit-domain-admins", "audit-administrators", "audit-unread",
         "ops-extra-ace", "ops-missing-ou", "ops-scan-cut", "ops-other-ou-same-count"],
)
def test_each_read_back_that_fails_stops_readback_failed(server: Server8, old: str, new: str, check: str) -> None:
    the_plan = _to_restart(server)
    out = _read_out()
    assert old in out
    result = _drive(server, _request(the_plan, action="status", helper=None), ops={"s8-read": _ok(out.replace(old, new))},
                    results={"s8-sshd": {"result": 0, "output": SSHD_OUT}})
    assert (result["answer"]["status"], result["answer"]["code"]) == ("stopped", "readback_failed"), result
    failed = [c["name"] for c in result["answer"]["checks"] if not c["ok"]]
    assert failed == [check], result["answer"]["checks"]
    assert _states(server)[-1] == ("stopped", "s8_restart")


def test_a_read_back_that_failed_stops_readback_failed(server: Server8) -> None:
    the_plan = _to_restart(server)
    result = _drive(server, _request(the_plan, action="status", helper=None),
                    ops={"s8-read": {"result": 1, "output": "FAIL: System.Exception: x\n"}},
                    results={"s8-sshd": {"result": 0, "output": SSHD_OUT}})
    assert (result["answer"]["status"], result["answer"]["code"]) == ("stopped", "readback_failed"), result


def test_a_read_back_still_running_at_its_wait_stops_readback_failed(server: Server8) -> None:
    """A read-back task that outlived its wait never lets stage 8 end done
    with nothing read back."""
    the_plan = _to_restart(server)
    result = _drive(server, _request(the_plan, action="status", helper=None),
                    ops={"s8-read": {"result": -1, "output": "", "outcome": "running"}},
                    results={"s8-sshd": {"result": 0, "output": SSHD_OUT}})
    assert (result["answer"]["status"], result["answer"]["code"]) == ("stopped", "readback_failed"), result
    failed = [c["name"] for c in result["answer"]["checks"] if not c["ok"]]
    assert failed == ["s8-read"], result["answer"]["checks"]
    assert _ops_called(result) == ["s8-read"]
    assert _states(server) == [("started", "s8_setup"), ("started", "s8_restart"), ("stopped", "s8_restart")]


def test_a_status_while_an_earlier_read_back_still_runs_answers_started(server: Server8) -> None:
    """Review finding 5 of task 8 part E: a session that dropped while
    s8-read ran in its task leaves that task running.  The next status
    neither starts a second read nor stops the stage: it answers started and
    records nothing."""
    the_plan = _to_restart(server)
    before = server.journal()
    result = _drive(server, _request(the_plan, action="status", helper=None), ops={"s8-read": _ok(_read_out())},
                    results={"s8-sshd": {"result": 0, "output": SSHD_OUT}}, running=["s8-read"])
    assert (result["answer"]["ok"], result["answer"]["status"]) == (True, "started"), result
    assert _ops_called(result) == []
    assert server.journal() == before


def test_a_status_after_an_earlier_read_back_ended_reads_its_result(server: Server8) -> None:
    """The read-back of the dropped session ended: its result file is read
    (the op is not run again) and the stage ends on it."""
    the_plan = _to_restart(server)
    result = _drive(server, _request(the_plan, action="status", helper=None),
                    results={"s8-sshd": {"result": 0, "output": SSHD_OUT}, "s8-read": {"result": 0, "output": _read_out()}})
    assert (result["answer"]["ok"], result["answer"]["status"]) == (True, "done"), result
    assert _ops_called(result) == []
    assert [c["op"] for c in result["calls"] if c["kind"] == "task-removed"] == ["s8-read"]
    names = [c["name"] for c in result["answer"]["checks"]]
    assert names == ["sshd_restart", "ops_login", "audit_login", "write_helper", "approval_key", "sshd_answers",
                     "audit_unprivileged", "ops_delegation"]
    assert _states(server)[-1] == ("done", "s8_restart")


def test_an_earlier_read_back_that_failed_stops_readback_failed(server: Server8) -> None:
    the_plan = _to_restart(server)
    bad = _read_out().replace("sshd service: Running", "sshd service: Stopped")
    result = _drive(server, _request(the_plan, action="status", helper=None),
                    results={"s8-sshd": {"result": 0, "output": SSHD_OUT}, "s8-read": {"result": 0, "output": bad}})
    assert (result["answer"]["status"], result["answer"]["code"]) == ("stopped", "readback_failed"), result
    assert _ops_called(result) == []


def test_the_run_of_stage_8_clears_an_older_read_back_result(server: Server8) -> None:
    """A read-back result the status may read is one of this run: the run
    clears s8-read's files before its started entry."""
    the_plan = _plan()
    _seed_to_8(server, the_plan)
    result = _drive(server, _request(the_plan), ops=_run_ops())
    cleared = [c["op"] for c in result["calls"] if c["kind"] == "clear"]
    assert "s8-read" in cleared
    first = next(c for c in result["calls"] if c["kind"] == "clear" and c["op"] == "s8-read")
    assert first["journal"] == len([e for e in server.journal() if e["stage"] != "8"])


#: The lines of s8-read that count and print newton-ops' explicit ACEs, as
#: the body holds them (review finding 6 of task 8 part E: a changed bound,
#: such as -gt 1, would drop the domain head's one ACE from the read-back).
S8_READ_ACE_LINES = [
    "    $explicit = @($object.nTSecurityDescriptor.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]) |",
    "        Where-Object { (-not $_.IsInherited) -and ([string]$_.IdentityReference -eq $opsSid) }).Count",
    "    if ($explicit -gt 0) { 'ops explicit aces: ' + $object.DistinguishedName + ' | ' + $explicit }",
]


def test_the_read_back_prints_every_object_with_an_explicit_ace_of_newton_ops(server: Server8) -> None:
    out = server.drive({"mode": "render", "ops": ["s8-read"], "values": {"Netbios": "NBUILD", "AdDir": "C:\\ProgramData\\Newton\\ad",
                                                                          "BuildKey": "C:\\ProgramData\\Newton\\ad-build\\key.hex"}})
    lines = out["scripts"]["s8-read"].splitlines()
    start = lines.index(S8_READ_ACE_LINES[0])
    assert lines[start:start + 3] == S8_READ_ACE_LINES
    assert sum(1 for line in lines if "'ops explicit aces: '" in line) == 1


def test_a_status_of_another_plan_at_the_restart_is_refused_plan_mismatch(server: Server8) -> None:
    """Stage 8 started under one plan: a status sent under a second plan
    of the same run (a resume plan that starts at 8) reads nothing back and
    records nothing."""
    the_plan = _to_restart(server)
    inputs = copy.deepcopy(PLAN_INPUTS)
    inputs["resume_from"] = plan.digest(the_plan)
    inputs["secrets_from"] = plan.digest(the_plan)
    inputs["start_stage"] = "8"
    other = plan.plan_build(inputs)
    assert plan.digest(other) != plan.digest(the_plan)
    before = server.journal()
    result = _drive(server, _request(other, action="status", helper=None), ops={"s8-read": _ok(_read_out())},
                    results={"s8-sshd": {"result": 0, "output": SSHD_OUT}})
    assert (result["answer"]["ok"], result["answer"]["code"]) == (False, "plan_mismatch"), result
    # refused by stage 8's own guard, not a later one
    assert "stage 8 was started under another plan" in result["error"], result
    assert _ops_called(result) == []
    assert server.journal() == before


def test_the_read_back_op_reads_what_the_design_names(server: Server8) -> None:
    out = server.drive({"mode": "render", "ops": ["s8-read"], "values": {"Netbios": "NBUILD", "AdDir": "C:\\ProgramData\\Newton\\ad",
                                                                          "BuildKey": "C:\\ProgramData\\Newton\\ad-build\\key.hex"}})
    text = out["scripts"]["s8-read"]
    for needle in ("'sshd match ' + $user", "write_authorized_keys", "'authorized_keys'", "Get-FileHash -Algorithm SHA256",
                   "approval.key", "Get-Service -Name sshd", "Connect('127.0.0.1', 22)", "tokenGroups",
                   "nTSecurityDescriptor", "IsInherited"):
        assert needle in text, needle
    # it writes nothing
    for verb in ("Set-", "New-AD", "Remove-", "Add-AD", "dsacls", "Restart-Service"):
        assert verb not in text, verb


# --------------------------------------------------------------------------
# the values of stage 8, out of the plan bytes
# --------------------------------------------------------------------------


def _ops_values(server: Server8, plan_bytes: bytes, role: str = "dc1") -> dict[str, Any]:
    return server.drive({"mode": "ops-values", "plan": base64.b64encode(plan_bytes).decode("ascii"), "role": role})


def test_newton_ops_is_delegated_the_plans_top_level_ous(server: Server8) -> None:
    inputs = copy.deepcopy(PLAN_INPUTS)
    inputs["domain"]["ou_tree"] = ["IT/Servers", "IT/Workstations", "Sales", "Sales/East"]
    out = _ops_values(server, plan.canonical_bytes(plan.plan_build(inputs)))
    values = out["values"]
    assert values["OpsOus"] == ["OU=IT,DC=build,DC=newton,DC=test", "OU=Sales,DC=build,DC=newton,DC=test"]
    assert values["DomainDn"] == "DC=build,DC=newton,DC=test"
    assert (values["OpsKey"], values["AuditKey"], values["WriteHelperSha"]) == (
        OPS["public_key"], OPS["audit_public_key"], OPS["write_helper_sha256"])
    assert (values["Device"], values["Ip"], values["DnsName"]) == ("build1", "192.0.2.41", "build.newton.test")


def test_the_values_of_stage_8_are_dc1s_only(server: Server8) -> None:
    inputs = copy.deepcopy(PLAN_INPUTS)
    inputs["servers"].append(dict(inputs["servers"][0], device="build2", role="dc2", hostname="BDC2", ip="192.0.2.42",
                                  vmgenid="0f5c9a44-3c51-4b6e-9d0a-6a1b2c3d4e5f"))
    two = plan.canonical_bytes(plan.plan_build(inputs))
    assert "values" in _ops_values(server, two, role="dc1")
    out = _ops_values(server, two, role="dc2")
    assert out.get("error") == "schema", out


@pytest.mark.parametrize(
    "old, new",
    [
        ("ops.audit_public_key=" + OPS["audit_public_key"], "ops.audit_public_key=" + OPS["public_key"]),
        ("ops.audit_public_key=" + OPS["audit_public_key"], "ops.audit_public_key=ssh-rsa AAAA"),
        ("ops.write_helper_sha256=" + OPS["write_helper_sha256"], "ops.write_helper_sha256=" + OPS["write_helper_sha256"].upper()),
        ("domain.ou_tree=IT/Servers\n", "domain.ou_tree=\n"),
    ],
    ids=["one-key-for-both", "audit-not-ed25519", "sha-not-lowercase", "no-ou"],
)
def test_plan_bytes_outside_stage_8s_grammar_are_refused(server: Server8, old: str, new: str) -> None:
    """The helper reads the plan bytes against its own grammar, whatever
    the planner checked."""
    raw = plan.canonical_bytes(_plan()).decode("utf-8")
    assert old in raw
    out = _ops_values(server, raw.replace(old, new).encode("utf-8"))
    assert out.get("error") == "schema", out


@pytest.mark.parametrize("op", ["s8-audit", "s8-ops"])
@pytest.mark.parametrize("line", ["setup exit 1", ""], ids=["exit-1", "no-exit-line"])
def test_a_setup_that_did_not_exit_0_stops_op_failed(server: Server8, op: str, line: str) -> None:
    """The 1.4 setup leaves with ``exit 1`` on some refusals; every step
    line printed before it does not make the setup a pass."""
    the_plan = _plan()
    _seed_to_8(server, the_plan)
    ops = _run_ops()
    out = _setup_out(op).replace("setup exit 0\n", (line + "\n") if line else "")
    ops[op] = _ok(out)
    result = _drive(server, _request(the_plan), ops=ops)
    assert (result["answer"]["status"], result["answer"]["code"]) == ("stopped", "op_failed"), result
    assert "s8-restart" not in _ops_called(result)


def test_the_helper_knows_every_step_line_of_each_build_template(server: Server8) -> None:
    import re

    out = server.drive({"mode": "render", "ops": ["s8-read"], "values": {"Netbios": "N", "AdDir": "x", "BuildKey": "y"}})
    assert out["scripts"]
    helper = (Path(setupgen.__file__).parent / "build" / "helper" / "build.ps1").read_text(encoding="utf-8")
    for op, template in (("s8-audit", setupgen.windows_template(build=True)),
                         ("s8-ops", setupgen_write.windows_write_template(build=True))):
        steps = re.findall(r"^Write-Host '(Step [0-9]+: [^']*)'$", template, re.MULTILINE)
        table = helper[helper.index("$script:SetupSteps = @{"):]
        listed = re.search(r"^    '" + op + r"' = @\(((?:.|\n)*?)\)$", table, re.MULTILINE)
        assert listed, op
        assert re.findall(r"'(Step [0-9]+: [^']*)'", listed.group(1)) == steps
