"""The build helper of Newton 1.5 (PLAN-1.5 task 3, DESIGN-1.5 "The helper").

The helper is the forced command of the server that becomes a domain
controller.  It reads one JSON request on stdin, recomputes the digest
of the canonical plan bytes the request carries, checks the token of
the request against it, keeps the journal of the run and refuses
everything the design refuses.

Every constant of this file comes from the design, from the plan model
of task 1 or from ``newton_mcp.approve``: the header line
``newton-ad-build-v1``, the stage digest message
``newton-ad-build-stage-v1`` with its ``plan=``, ``stage=`` and
``checkpoint=`` lines, the HMAC of ``approval_token`` and the two stage
graphs of the plan.

The tokens of these tests are minted by ``newton_mcp.approve`` itself,
so the helper and the host agree on the bytes of the token and not
only on the shape of it.

The stage table of these tests is a FAKE one: the real stage templates
are tasks 5 to 8.  A fake entry says only whether its stage reboots,
whether the connection drops after the terminal entry of the stage and
which checks the stage reports.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest

from newton_mcp.ad.build import plan
from newton_mcp.approve import approval_token, derive_k
from ops_fixture import OPS  # type: ignore[import-not-found]
from pwsh_path import PWSH


#: The helper of the build, under the package of the plan model.
HELPER = (
    Path(__file__).resolve().parents[3]
    / "newton_mcp"
    / "ad"
    / "build"
    / "helper"
    / "build.ps1"
)

#: The key of the server: 64 lowercase hexadecimal characters.  It is
#: synthetic; one test derives a key the way the bootstrap does.
KEY_HEX = "a1" * 32

#: The clock of the tests: 2026-11-12T00:00:00Z.
BASE = 1794441600

#: The window of the tokens of the tests: one minute back, one hour on.
NBF = BASE - 60
EXP = BASE + 3600

#: The run id of the tests: 32 lowercase hexadecimal characters.
RUN = "b2" * 16

#: The boot time of the tests, before and after the reboot.
BOOT_BEFORE = "2026-11-12T00:00:00Z"
BOOT_AFTER = "2026-11-12T00:10:00Z"

#: The plan of the tests: one domain, two servers, one baseline
#: option.  Every value is synthetic (RFC 5737 addresses).
PLAN_INPUTS: dict[str, Any] = {
    "domain": {
        "dns_name": "ad-build.test",
        "netbios": "ADBUILD",
        "functional_level": "Win2025",
        "site": "Default-First-Site-Name",
        "ou_tree": ["IT/Servers"],
        "groups": ["IT Admins"],
        "owner_admin": "owner-admin",
    },
    "servers": [
        {
            "device": "build1",
            "role": "dc1",
            "hostname": "DC1",
            "ip": "192.0.2.11",
            "prefix": 24,
            "gateway": "192.0.2.1",
            "forwarders": ["192.0.2.53"],
            "checkpoint": "hyperv",
        },
        {
            "device": "build2",
            "role": "dc2",
            "hostname": "DC2",
            "ip": "192.0.2.12",
            "prefix": 24,
            "gateway": "192.0.2.1",
            "forwarders": ["192.0.2.53"],
            "checkpoint": "wbadmin",
        },
    ],
    "baseline": {
        "version": "2026.11",
        "options": {"administrator": "random-password"},
    },
    "accepted_findings": [],
    "ops": dict(OPS),
}

#: The fake stage table of the tests.  Stage 1 and stage 2 reboot, the
#: way the design says they do.
STAGE_TABLE: dict[str, Any] = {
    "0": {
        "reboot": False,
        "drop": False,
        "checks": [{"name": "os", "ok": True, "detail": "Server 2025"}],
    },
    "1": {"reboot": True, "drop": False, "checks": []},
    "2": {"reboot": True, "drop": False, "checks": []},
    "3": {"reboot": False, "drop": False, "checks": []},
    "4": {"reboot": False, "drop": False, "checks": []},
    "5": {"reboot": False, "drop": False, "checks": []},
    "6": {"reboot": False, "drop": False, "checks": []},
    "7": {"reboot": True, "drop": False, "checks": []},
    "8": {"reboot": False, "drop": False, "checks": []},
    "9": {"reboot": False, "drop": False, "checks": []},
    "10": {"reboot": False, "drop": False, "checks": []},
}


def _plan(inputs: dict[str, Any] | None = None) -> dict[str, Any]:
    """The plan of the tests, built by the model of task 1."""
    return plan.plan_build(copy.deepcopy(PLAN_INPUTS if inputs is None else inputs))


def _canonical(the_plan: dict[str, Any]) -> bytes:
    """The canonical bytes of a plan: what the request carries."""
    return plan.canonical_bytes(the_plan)


def _token(digest: str, *, key: str = KEY_HEX, nbf: int = NBF, exp: int = EXP) -> str:
    """A token of the approve module, over a digest."""
    return approval_token(key, digest, nbf, exp)


def _request(
    the_plan: dict[str, Any],
    *,
    stage: str = "0",
    action: str = "run",
    token: str | None = None,
    nbf: int = NBF,
    exp: int = EXP,
    run: str = RUN,
) -> dict[str, Any]:
    """One request of the contract: the plan bytes and the rest."""
    return {
        "run": run,
        "plan": base64.b64encode(_canonical(the_plan)).decode("ascii"),
        "stage": stage,
        "action": action,
        "token": _token(plan.digest(the_plan), nbf=nbf, exp=exp) if token is None else token,
        "nbf": nbf,
        "exp": exp,
    }


class _DefaultTable:
    """The marker of the default table of a server.

    The default is the fake table of the install root of the tests; a
    request with ``table=None`` names no table at all.
    """


#: The marker of the default table of a server.
DEFAULT_TABLE = _DefaultTable()


class Server:
    """The install root of a server: its key, its name and its journal."""

    def __init__(self, root: Path, *, key_hex: str = KEY_HEX, device: str = "build1") -> None:
        self.root = root
        self.key_hex = key_hex
        self.device = device
        root.mkdir(parents=True, exist_ok=True)
        (root / "key.hex").write_text(key_hex + "\n", encoding="ascii")
        (root / "device.txt").write_text(device + "\n", encoding="ascii")

    def write_table(self, table: dict[str, Any]) -> Path:
        """The fake stage table of the server."""
        path = self.root / "stages.json"
        path.write_text(json.dumps(table), encoding="ascii")
        return path

    def journal(self, run: str = RUN) -> list[dict[str, Any]]:
        """The entries of the journal of one run, in the order of the seq."""
        directory = self.root / "journal"
        if not directory.is_dir():
            return []
        entries: list[dict[str, Any]] = []
        for path in sorted(directory.iterdir()):
            if not path.name.startswith(run + "."):
                continue
            entries.append(json.loads(path.read_text(encoding="utf-8")))
        entries.sort(key=lambda entry: entry["seq"])
        return entries

    def names(self, run: str = RUN) -> list[str]:
        """The names of the journal files of one run."""
        directory = self.root / "journal"
        if not directory.is_dir():
            return []
        return sorted(path.name for path in directory.iterdir() if path.name.startswith(run + "."))

    def call(
        self,
        request: Any,
        *,
        now: int | None = None,
        boot: str | None = None,
        table: Path | None | _DefaultTable = DEFAULT_TABLE,
        env: dict[str, str] | None = None,
    ) -> tuple[subprocess.CompletedProcess[str], dict[str, Any] | None]:
        """One request to the helper, with the answer it wrote."""
        return self.call_raw(
            json.dumps(request) if not isinstance(request, str) else request,
            now=now,
            boot=boot,
            table=table,
            env=env,
        )

    def call_raw(
        self,
        text: str,
        *,
        now: int | None = None,
        boot: str | None = None,
        table: Path | None | _DefaultTable = DEFAULT_TABLE,
        env: dict[str, str] | None = None,
    ) -> tuple[subprocess.CompletedProcess[str], dict[str, Any] | None]:
        """One request to the helper, as raw text on stdin."""
        if isinstance(table, _DefaultTable):
            candidate = self.root / "stages.json"
            table = candidate if candidate.is_file() else None
        args = [
            str(PWSH),
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(HELPER),
            "-InstallRoot",
            str(self.root),
        ]
        if now is not None:
            args += ["-Now", str(now)]
        if boot is not None:
            args += ["-BootTime", boot]
        if table is not None:
            args += ["-StageTablePath", str(table)]
        child_env = None
        if env is not None:
            child_env = os.environ.copy()
            child_env.update(env)
        result = subprocess.run(
            args,
            input=text,
            capture_output=True,
            text=True,
            timeout=300,
            env=child_env,
        )
        answer: dict[str, Any] | None = None
        if result.stdout.strip():
            answer = json.loads(result.stdout)
        return result, answer


@pytest.fixture
def server(tmp_path: Path) -> Server:
    """A server with its fake stage table."""
    one = Server(tmp_path / "install")
    one.write_table(STAGE_TABLE)
    return one


def _complete(
    server: Server,
    the_plan: dict[str, Any],
    stage: str,
    *,
    token: str | None = None,
    now: int = BASE,
) -> dict[str, Any]:
    """Run one stage and let its reboot happen."""
    request = _request(the_plan, stage=stage, token=token)
    _, answer = server.call(request, now=now, boot=BOOT_BEFORE)
    assert answer is not None
    if answer.get("status") == "rebooting":
        request = _request(the_plan, stage=stage, action="status", token=token)
        _, answer = server.call(request, now=now, boot=BOOT_AFTER)
        assert answer is not None
    return answer


# ---------------------------------------------------------------------------
# the contract of the request
# ---------------------------------------------------------------------------


def test_the_helper_answers_with_the_four_fields_of_the_design(server: Server) -> None:
    """The answer is {ok, status, code, checks} and nothing else."""
    the_plan = _plan()
    _, answer = server.call(_request(the_plan), now=BASE, boot=BOOT_BEFORE)
    assert answer is not None
    assert set(answer) == {"ok", "status", "code", "checks"}
    assert answer["ok"] is True
    assert answer["code"] == ""
    assert answer["status"] == "done"
    assert answer["checks"] == [
        {"name": "os", "ok": True, "detail": "Server 2025"},
    ]


def test_the_helper_refuses_a_request_that_is_not_the_contract(server: Server) -> None:
    """A request outside the contract is a schema refusal."""
    the_plan = _plan()
    good = _request(the_plan)

    without_stage = dict(good)
    del without_stage["stage"]
    result, answer = server.call(without_stage, now=BASE, boot=BOOT_BEFORE)
    assert answer is not None
    assert answer["ok"] is False
    assert answer["code"] == "schema"
    # a refusal before the lock of the journal still exits 0
    assert result.returncode == 0
    assert "JournalLock" not in result.stderr

    other_action = dict(good)
    other_action["action"] = "apply"
    _, answer = server.call(other_action, now=BASE, boot=BOOT_BEFORE)
    assert answer is not None
    assert answer["code"] == "schema"

    not_base64 = dict(good)
    not_base64["plan"] = "not base64 ***"
    _, answer = server.call(not_base64, now=BASE, boot=BOOT_BEFORE)
    assert answer is not None
    assert answer["code"] == "schema"

    _, answer = server.call_raw("this is not json", now=BASE, boot=BOOT_BEFORE)
    assert answer is not None
    assert answer["code"] == "schema"


def test_the_helper_refuses_a_duplicate_key(server: Server) -> None:
    """A key written twice is a schema refusal: the run is not signed,
    so a second run key must not silently pick the run written to."""
    the_plan = _plan()
    other_run = "c3" * 16
    text = json.dumps(_request(the_plan))
    assert text.startswith("{")
    duplicate = '{"run": "' + other_run + '", ' + text[1:]
    _, answer = server.call_raw(duplicate, now=BASE, boot=BOOT_BEFORE)
    assert answer is not None
    assert answer["ok"] is False
    assert answer["code"] == "schema"
    assert server.names() == []
    assert server.names(other_run) == []

    # two keys that differ only in case are refused the same way
    colliding = '{"Run": "' + other_run + '", ' + text[1:]
    _, answer = server.call_raw(colliding, now=BASE, boot=BOOT_BEFORE)
    assert answer is not None
    assert answer["ok"] is False
    assert answer["code"] == "schema"
    assert server.names() == []
    assert server.names(other_run) == []


def test_the_helper_refuses_a_plan_that_is_not_the_canonical_plan(server: Server) -> None:
    """A plan without the header of the plan is a schema refusal."""
    the_plan = _plan()
    request = _request(the_plan)
    request["plan"] = base64.b64encode(b"domain.dns_name=ad-build.test\n").decode("ascii")
    _, answer = server.call(request, now=BASE, boot=BOOT_BEFORE)
    assert answer is not None
    assert answer["code"] == "schema"


def test_the_helper_takes_the_key_of_the_server_at_the_path_it_is_given(
    tmp_path: Path,
) -> None:
    """The path of the key is a parameter of the helper."""
    one = Server(tmp_path / "install")
    table = one.write_table(STAGE_TABLE)
    key = "d4" * 32
    key_path = tmp_path / "elsewhere" / "the.key"
    key_path.parent.mkdir(parents=True)
    key_path.write_text(key + "\n", encoding="ascii")

    the_plan = _plan()
    request = _request(the_plan, token=_token(plan.digest(the_plan), key=key))
    args = [
        str(PWSH),
        "-NoProfile",
        "-NonInteractive",
        "-File",
        str(HELPER),
        "-InstallRoot",
        str(one.root),
        "-KeyPath",
        str(key_path),
        "-Now",
        str(BASE),
        "-BootTime",
        BOOT_BEFORE,
        "-StageTablePath",
        str(table),
    ]
    result = subprocess.run(
        args, input=json.dumps(request), capture_output=True, text=True, timeout=300
    )
    answer = json.loads(result.stdout)
    assert answer["ok"] is True
    assert answer["status"] == "done"


def test_the_helper_refuses_a_token_it_cannot_verify(server: Server) -> None:
    """A token that is not the token of the plan is bad_token."""
    the_plan = _plan()
    request = _request(the_plan, token="0" * 64)
    _, answer = server.call(request, now=BASE, boot=BOOT_BEFORE)
    assert answer is not None
    assert answer["ok"] is False
    assert answer["code"] == "bad_token"
    assert server.journal() == []


def test_the_helper_refuses_a_token_whose_window_has_passed(server: Server) -> None:
    """A token of a window that is over is expired."""
    the_plan = _plan()
    request = _request(the_plan, nbf=BASE - 7200, exp=BASE - 3600)
    _, answer = server.call(request, now=BASE, boot=BOOT_BEFORE)
    assert answer is not None
    assert answer["ok"] is False
    assert answer["code"] == "expired"


def test_the_helper_refuses_a_token_whose_window_has_not_opened(server: Server) -> None:
    """A token of a window that is not open yet is expired."""
    the_plan = _plan()
    request = _request(the_plan, nbf=BASE + 3600, exp=BASE + 7200)
    _, answer = server.call(request, now=BASE, boot=BOOT_BEFORE)
    assert answer is not None
    assert answer["ok"] is False
    assert answer["code"] == "expired"


def _design_tables(text: str) -> tuple[dict[str, str], dict[str, str]]:
    """The stage kinds and the three graphs the helper holds, parsed out
    of the text of build.ps1."""
    block = re.search(r"\$script:DesignStageKinds = @\{\n(.*?)\n\}", text, re.S)
    assert block is not None
    kinds = dict(re.findall(r"^\s*'(\d+)' = '([a-z]+)'\s*$", block.group(1), re.M))
    graphs = dict(re.findall(r"^\$script:(DesignGraph\w+) = '([0-9,]+)'\s*$", text, re.M))
    return kinds, graphs


def _assert_design_tables_match_the_plan_model(text: str) -> None:
    kinds, graphs = _design_tables(text)
    assert kinds == plan.STAGE_KINDS
    assert graphs == {
        "DesignGraphDc1": ",".join(plan.DC1_GRAPH),
        "DesignGraphDc1Alone": ",".join(plan.DC1_GRAPH_ALONE),
        "DesignGraphDc2": ",".join(plan.DC2_GRAPH),
    }


def test_the_helper_holds_the_kinds_and_graphs_of_the_plan_model() -> None:
    """The kinds and graphs of build.ps1 are the ones of plan.py."""
    _assert_design_tables_match_the_plan_model(HELPER.read_text(encoding="utf-8"))


def test_the_helper_refuses_the_same_owner_admin_names_as_the_plan() -> None:
    """The helper's second check of the plan refuses every name plan.py
    reserves for the owner's admin account, no more and no fewer."""
    text = HELPER.read_text(encoding="utf-8")
    found = re.search(r"^\$script:ReservedOwnerAdmins = @\(([^)]*)\)$", text, re.MULTILINE)
    assert found is not None
    names = set(re.findall(r"'([^']*)'", found.group(1)))
    assert names == set(plan.RESERVED_OWNER_ADMINS)


# ---------------------------------------------------------------------------
# the order of the stages
# ---------------------------------------------------------------------------


def test_the_helper_refuses_a_stage_that_is_not_the_next_one(server: Server) -> None:
    """A stage that is not next in the graph of the server is out_of_order."""
    the_plan = _plan()
    request = _request(the_plan, stage="5")
    _, answer = server.call(request, now=BASE, boot=BOOT_BEFORE)
    assert answer is not None
    assert answer["ok"] is False
    assert answer["code"] == "out_of_order"
    assert server.journal() == []


def test_the_helper_refuses_a_stage_that_is_done(server: Server) -> None:
    """A stage that is already done is already_done."""
    the_plan = _plan()
    _, answer = server.call(_request(the_plan), now=BASE, boot=BOOT_BEFORE)
    assert answer is not None
    assert answer["status"] == "done"

    _, answer = server.call(_request(the_plan), now=BASE, boot=BOOT_BEFORE)
    assert answer is not None
    assert answer["ok"] is False
    assert answer["code"] == "already_done"


def test_the_helper_follows_the_graph_of_its_own_server(tmp_path: Path) -> None:
    """The helper reads the graph of its own server out of the plan bytes."""
    table = copy.deepcopy(STAGE_TABLE)
    table["1"]["reboot"] = False
    one = Server(tmp_path / "install", device="build2")
    one.write_table(table)
    the_plan = _plan()

    # stage 5 is in the graph of dc1 and not in the graph of dc2
    _, answer = one.call(_request(the_plan, stage="5"), now=BASE, boot=BOOT_BEFORE)
    assert answer is not None
    assert answer["code"] == "out_of_order"

    # stage 3 is in the graph of dc1 and not in the graph of dc2
    _, answer = one.call(_request(the_plan, stage="3"), now=BASE, boot=BOOT_BEFORE)
    assert answer is not None
    assert answer["code"] == "out_of_order"

    # the stages of the graph of dc2 run in its order
    answer = _complete(one, the_plan, "0")
    assert answer["status"] == "done"
    answer = _complete(one, the_plan, "1")
    assert answer["status"] == "done"

    # stage 2 is next in the graph of dc1 and not in the graph of dc2
    _, answer = one.call(_request(the_plan, stage="2"), now=BASE, boot=BOOT_BEFORE)
    assert answer is not None
    assert answer["code"] == "out_of_order"


# ---------------------------------------------------------------------------
# the plan of the run
# ---------------------------------------------------------------------------


def test_the_helper_refuses_a_plan_byte_that_changed(server: Server) -> None:
    """One changed byte of the plan is bad_token, even with the old token."""
    the_plan = _plan()
    original = _canonical(the_plan)
    _, answer = server.call(_request(the_plan), now=BASE, boot=BOOT_BEFORE)
    assert answer is not None
    assert answer["ok"] is True

    changed = original.replace(b"Default-First-Site-Name", b"Default-First-Site-Namf")
    assert len(changed) == len(original)
    assert changed != original
    request = _request(the_plan)
    request["plan"] = base64.b64encode(changed).decode("ascii")
    _, answer = server.call(request, now=BASE, boot=BOOT_BEFORE)
    assert answer is not None
    assert answer["ok"] is False
    assert answer["code"] == "bad_token"


def test_the_helper_refuses_a_second_run_of_a_stage_that_is_in_flight(
    server: Server,
) -> None:
    """A stage that waits for a reboot does not run twice under one plan."""
    the_plan = _plan()
    answer = _complete(server, the_plan, "0")
    assert answer["status"] == "done"

    _, answer = server.call(_request(the_plan, stage="1"), now=BASE, boot=BOOT_BEFORE)
    assert answer is not None
    assert answer["status"] == "rebooting"

    _, answer = server.call(_request(the_plan, stage="1"), now=BASE, boot=BOOT_BEFORE)
    assert answer is not None
    assert answer["ok"] is False
    assert answer["code"] == "out_of_order"


def test_the_helper_refuses_another_plan_for_the_same_run(server: Server) -> None:
    """A plan whose digest is not the digest of the run is plan_mismatch."""
    the_plan = _plan()
    _, answer = server.call(_request(the_plan), now=BASE, boot=BOOT_BEFORE)
    assert answer is not None
    assert answer["ok"] is True

    other_inputs = copy.deepcopy(PLAN_INPUTS)
    other_inputs["domain"]["dns_name"] = "other-build.test"
    other = _plan(other_inputs)
    assert plan.digest(other) != plan.digest(the_plan)

    _, answer = server.call(_request(other, stage="1"), now=BASE, boot=BOOT_BEFORE)
    assert answer is not None
    assert answer["ok"] is False
    assert answer["code"] == "plan_mismatch"

    # the other plan sent for an irreversible stage is plan_mismatch as
    # well, and not a stage with no checkpoint
    assert _complete(server, the_plan, "1")["status"] == "done"
    before = server.journal()
    token = _token(plan.stage_digest(plan.digest(other), "2", "fake-cp-2-0"))
    _, answer = server.call(
        _request(other, stage="2", token=token), now=BASE, boot=BOOT_BEFORE
    )
    assert answer is not None
    assert answer["ok"] is False
    assert answer["code"] == "plan_mismatch"
    assert server.journal() == before


def test_the_helper_accepts_a_resume_chain(server: Server) -> None:
    """A plan that resumes the run of the journal is accepted."""
    the_plan = _plan()
    _, answer = server.call(_request(the_plan), now=BASE, boot=BOOT_BEFORE)
    assert answer is not None
    assert answer["ok"] is True

    resumed_inputs = copy.deepcopy(PLAN_INPUTS)
    resumed_inputs["resume_from"] = plan.digest(the_plan)
    resumed_inputs["secrets_from"] = plan.digest(the_plan)
    resumed_inputs["start_stage"] = "1"
    resumed = _plan(resumed_inputs)

    _, answer = server.call(_request(resumed, stage="1"), now=BASE, boot=BOOT_BEFORE)
    assert answer is not None
    assert answer["ok"] is True
    assert answer["status"] == "rebooting"
    entries = server.journal()
    assert entries[-1]["digest"] == plan.digest(resumed)


def test_the_helper_refuses_a_resume_chain_that_starts_at_the_wrong_stage(
    server: Server,
) -> None:
    """A resume that does not start at the next stage of the journal is refused."""
    the_plan = _plan()
    _, answer = server.call(_request(the_plan), now=BASE, boot=BOOT_BEFORE)
    assert answer is not None
    assert answer["ok"] is True

    resumed_inputs = copy.deepcopy(PLAN_INPUTS)
    resumed_inputs["resume_from"] = plan.digest(the_plan)
    resumed_inputs["secrets_from"] = plan.digest(the_plan)
    resumed_inputs["start_stage"] = "5"
    resumed = _plan(resumed_inputs)

    _, answer = server.call(_request(resumed, stage="5"), now=BASE, boot=BOOT_BEFORE)
    assert answer is not None
    assert answer["ok"] is False
    assert answer["code"] == "plan_mismatch"


def _resume_plan(the_plan: dict[str, Any], start_stage: str) -> dict[str, Any]:
    """A plan that resumes the run of ``the_plan`` at ``start_stage``."""
    resumed_inputs = copy.deepcopy(PLAN_INPUTS)
    resumed_inputs["resume_from"] = plan.digest(the_plan)
    resumed_inputs["secrets_from"] = plan.digest(the_plan)
    resumed_inputs["start_stage"] = start_stage
    return _plan(resumed_inputs)


def _stop_stage_two(server: Server, the_plan: dict[str, Any]) -> str:
    """Stages 0 and 1 done, then stage 2 checkpointed, run and stopped
    by the grace; the id of its checkpoint."""
    digest = plan.digest(the_plan)
    assert _complete(server, the_plan, "0")["status"] == "done"
    assert _complete(server, the_plan, "1")["status"] == "done"
    _, answer = server.call(
        _request(the_plan, stage="2", action="checkpoint"), now=BASE, boot=BOOT_BEFORE
    )
    assert answer is not None
    assert answer["status"] == "checkpointed"
    checkpoint = _checkpoint_id(server)
    token = _token(plan.stage_digest(digest, "2", checkpoint))
    _, answer = server.call(
        _request(the_plan, stage="2", token=token), now=BASE, boot=BOOT_BEFORE
    )
    assert answer is not None
    assert answer["status"] == "rebooting"
    _, answer = server.call(
        _request(the_plan, stage="2", action="status", token=token),
        now=EXP + 901,
        boot=BOOT_AFTER,
    )
    assert answer is not None
    assert answer["code"] == "expired"
    assert server.journal()[-1]["state"] == "stopped"
    return checkpoint


def test_the_helper_resumes_a_stopped_irreversible_stage(server: Server) -> None:
    """A resume plan reruns an irreversible stage the grace stopped."""
    the_plan = _plan()
    checkpoint_a = _stop_stage_two(server, the_plan)

    # a new token of the old plan does not run the stopped stage again
    token_a = _token(plan.stage_digest(plan.digest(the_plan), "2", checkpoint_a))
    _, answer = server.call(
        _request(the_plan, stage="2", token=token_a), now=BASE, boot=BOOT_BEFORE
    )
    assert answer is not None
    assert answer["ok"] is False
    assert answer["code"] == "out_of_order"

    # the resume plan takes its own checkpoint and runs the stage
    resumed = _resume_plan(the_plan, "2")
    _, answer = server.call(
        _request(resumed, stage="2", action="checkpoint"), now=BASE, boot=BOOT_BEFORE
    )
    assert answer is not None
    assert answer["ok"] is True
    assert answer["status"] == "checkpointed"
    checkpoint_b = _checkpoint_id(server)
    token_b = _token(plan.stage_digest(plan.digest(resumed), "2", checkpoint_b))
    _, answer = server.call(
        _request(resumed, stage="2", token=token_b), now=BASE, boot=BOOT_BEFORE
    )
    assert answer is not None
    assert answer["ok"] is True
    assert answer["status"] == "rebooting"
    assert server.journal()[-1]["digest"] == plan.digest(resumed)


def test_a_resume_plan_does_not_reuse_the_checkpoint_of_the_old_plan(
    server: Server,
) -> None:
    """The checkpoint of a stage binds the plan it was taken under."""
    the_plan = _plan()
    checkpoint_a = _stop_stage_two(server, the_plan)
    before = server.journal()

    resumed = _resume_plan(the_plan, "2")
    token = _token(plan.stage_digest(plan.digest(resumed), "2", checkpoint_a))
    result, answer = server.call(
        _request(resumed, stage="2", token=token), now=BASE, boot=BOOT_BEFORE
    )
    assert answer is not None
    assert answer["ok"] is False
    assert answer["code"] == "schema"
    assert "no checkpoint to bind" in result.stderr
    assert server.journal() == before


def test_the_helper_resumes_a_stage_left_started(server: Server) -> None:
    """A stage left started with no terminal entry is resumed by a new plan."""
    the_plan = _plan()
    assert _complete(server, the_plan, "0")["status"] == "done"
    assert len(server.journal()) == 2

    # the helper died after the entry of the start of stage 1
    started = {
        "run": RUN,
        "seq": 2,
        "stage": "1",
        "state": "started",
        "reason": "",
        "digest": plan.digest(the_plan),
        "checkpoint": "",
        "boot": "2026-11-12T00:00:00.0000000Z",
        "time": BASE,
        "checks": [],
    }
    (server.root / "journal" / f"{RUN}.2.json").write_text(
        json.dumps(started), encoding="utf-8"
    )

    resumed = _resume_plan(the_plan, "1")
    _, answer = server.call(_request(resumed, stage="1"), now=BASE, boot=BOOT_BEFORE)
    assert answer is not None
    assert answer["ok"] is True
    assert answer["status"] == "rebooting"
    assert server.journal()[-1]["digest"] == plan.digest(resumed)


def test_the_helper_refuses_a_resume_over_a_stage_in_flight(server: Server) -> None:
    """A resume does not start again a stage that waits for a reboot."""
    the_plan = _plan()
    answer = _complete(server, the_plan, "0")
    assert answer["status"] == "done"
    _, answer = server.call(_request(the_plan, stage="1"), now=BASE, boot=BOOT_BEFORE)
    assert answer is not None
    assert answer["status"] == "rebooting"
    before = len(server.journal())

    resumed_inputs = copy.deepcopy(PLAN_INPUTS)
    resumed_inputs["resume_from"] = plan.digest(the_plan)
    resumed_inputs["secrets_from"] = plan.digest(the_plan)
    resumed_inputs["start_stage"] = "1"
    resumed = _plan(resumed_inputs)

    _, answer = server.call(_request(resumed, stage="1"), now=BASE, boot=BOOT_BEFORE)
    assert answer is not None
    assert answer["ok"] is False
    assert answer["code"] == "out_of_order"
    assert len(server.journal()) == before


def test_a_foreign_plan_cannot_stop_a_stage(server: Server) -> None:
    """A plan of another build never writes to the journal of this one."""
    the_plan = _plan()
    answer = _complete(server, the_plan, "0")
    assert answer["status"] == "done"
    _, answer = server.call(_request(the_plan, stage="1"), now=BASE, boot=BOOT_BEFORE)
    assert answer is not None
    assert answer["status"] == "rebooting"
    before = server.journal()

    other_inputs = copy.deepcopy(PLAN_INPUTS)
    other_inputs["domain"]["dns_name"] = "other-build.test"
    other = _plan(other_inputs)

    _, answer = server.call(
        _request(other, stage="1", action="status"),
        now=EXP + 1000,
        boot=BOOT_AFTER,
    )
    assert answer is not None
    assert answer["ok"] is False
    assert answer["code"] == "plan_mismatch"
    assert server.journal() == before

    # and the other plan does not stop the stage either
    _, answer = server.call(
        _request(other, stage="1", action="status"), now=BASE, boot=BOOT_AFTER
    )
    assert answer is not None
    assert answer["ok"] is False
    assert answer["code"] == "plan_mismatch"
    assert server.journal() == before

    # the plan of the run is not locked out
    _, answer = server.call(
        _request(the_plan, stage="1", action="status"), now=BASE, boot=BOOT_BEFORE
    )
    assert answer is not None
    assert answer["ok"] is True
    assert answer["status"] == "rebooting"


def test_the_helper_refuses_a_second_run_id_on_one_server(server: Server) -> None:
    """One run per server: a second run id is a second build."""
    the_plan = _plan()
    answer = _complete(server, the_plan, "0")
    assert answer["status"] == "done"

    other_run = "c3" * 16
    _, answer = server.call(
        _request(the_plan, run=other_run), now=BASE, boot=BOOT_BEFORE
    )
    assert answer is not None
    assert answer["ok"] is False
    assert answer["code"] in {"plan_mismatch", "out_of_order"}
    assert server.names(other_run) == []

    # a plan of another build under a new run id is refused as well
    other_inputs = copy.deepcopy(PLAN_INPUTS)
    other_inputs["domain"]["dns_name"] = "other-build.test"
    other = _plan(other_inputs)
    _, answer = server.call(
        _request(other, run=other_run), now=BASE, boot=BOOT_BEFORE
    )
    assert answer is not None
    assert answer["ok"] is False
    assert answer["code"] == "plan_mismatch"
    assert server.names(other_run) == []

    # the run of the server is untouched
    entries = server.journal()
    assert [entry["state"] for entry in entries] == ["started", "done"]


# ---------------------------------------------------------------------------
# the tokens of the stages
# ---------------------------------------------------------------------------


def test_the_stage_token_opens_an_irreversible_stage_and_the_plan_token_does_not(
    server: Server,
) -> None:
    """An irreversible stage wants the token of its stage digest."""
    the_plan = _plan()
    digest = plan.digest(the_plan)

    # the stages before stage 2 are done
    answer = _complete(server, the_plan, "0")
    assert answer["status"] == "done"
    answer = _complete(server, the_plan, "1")
    assert answer["status"] == "done"

    # the helper takes the checkpoint itself, under the plan token
    _, answer = server.call(
        _request(the_plan, stage="2", action="checkpoint"), now=BASE, boot=BOOT_BEFORE
    )
    assert answer is not None
    assert answer["ok"] is True
    assert answer["status"] == "checkpointed"
    checkpoint = _checkpoint_id(server)
    assert checkpoint != ""

    # the plan token does not open stage 2
    _, answer = server.call(_request(the_plan, stage="2"), now=BASE, boot=BOOT_BEFORE)
    assert answer is not None
    assert answer["ok"] is False
    assert answer["code"] == "bad_token"

    # the stage token is the token of the stage digest
    stage_digest = plan.stage_digest(digest, "2", checkpoint)
    stage_token = _token(stage_digest)
    request = _request(the_plan, stage="2", token=stage_token)
    _, answer = server.call(request, now=BASE, boot=BOOT_BEFORE)
    assert answer is not None
    assert answer["ok"] is True
    assert answer["status"] == "rebooting"


def test_the_helper_refuses_an_irreversible_stage_without_a_checkpoint(
    server: Server,
) -> None:
    """A stage token cannot be checked before the checkpoint is taken."""
    the_plan = _plan()
    digest = plan.digest(the_plan)
    token = _token(plan.stage_digest(digest, "2", "fake-cp-2-0"))
    _, answer = server.call(
        _request(the_plan, stage="2", token=token), now=BASE, boot=BOOT_BEFORE
    )
    assert answer is not None
    assert answer["ok"] is False
    assert answer["code"] == "schema"
    assert server.journal() == []


def test_the_helper_refuses_the_stage_token_of_another_stage(server: Server) -> None:
    """The token of a stage does not open another stage."""
    the_plan = _plan()
    digest = plan.digest(the_plan)
    answer = _complete(server, the_plan, "0")
    assert answer["status"] == "done"
    answer = _complete(server, the_plan, "1")
    assert answer["status"] == "done"
    _, answer = server.call(
        _request(the_plan, stage="2", action="checkpoint"), now=BASE, boot=BOOT_BEFORE
    )
    assert answer is not None
    assert answer["ok"] is True
    checkpoint = _checkpoint_id(server)

    other = _token(plan.stage_digest(digest, "3", checkpoint))
    _, answer = server.call(
        _request(the_plan, stage="2", token=other), now=BASE, boot=BOOT_BEFORE
    )
    assert answer is not None
    assert answer["ok"] is False
    assert answer["code"] == "bad_token"


def test_the_helper_refuses_a_stage_token_over_another_checkpoint(server: Server) -> None:
    """The checkpoint id is in the signed bytes of the stage token."""
    the_plan = _plan()
    digest = plan.digest(the_plan)
    answer = _complete(server, the_plan, "0")
    assert answer["status"] == "done"
    answer = _complete(server, the_plan, "1")
    assert answer["status"] == "done"
    _, answer = server.call(
        _request(the_plan, stage="2", action="checkpoint"), now=BASE, boot=BOOT_BEFORE
    )
    assert answer is not None
    assert answer["ok"] is True

    wrong = _token(plan.stage_digest(digest, "2", "fake-cp-2-999"))
    _, answer = server.call(
        _request(the_plan, stage="2", token=wrong), now=BASE, boot=BOOT_BEFORE
    )
    assert answer is not None
    assert answer["ok"] is False
    assert answer["code"] == "bad_token"


def test_the_helper_refuses_a_checkpoint_for_a_stage_that_is_not_next(
    server: Server,
) -> None:
    """A checkpoint is taken for the next stage of the graph only."""
    the_plan = _plan()
    _, answer = server.call(
        _request(the_plan, stage="6", action="checkpoint"), now=BASE, boot=BOOT_BEFORE
    )
    assert answer is not None
    assert answer["ok"] is False
    assert answer["code"] == "out_of_order"
    assert server.journal() == []


def test_a_later_checkpoint_does_not_void_the_stage_token(server: Server) -> None:
    """A checkpoint of another stage does not void the token of this one."""
    the_plan = _plan()
    digest = plan.digest(the_plan)
    answer = _complete(server, the_plan, "0")
    assert answer["status"] == "done"
    answer = _complete(server, the_plan, "1")
    assert answer["status"] == "done"

    _, answer = server.call(
        _request(the_plan, stage="2", action="checkpoint"), now=BASE, boot=BOOT_BEFORE
    )
    assert answer is not None
    assert answer["ok"] is True
    checkpoint = _checkpoint_id(server)
    assert checkpoint != ""
    token = _token(plan.stage_digest(digest, "2", checkpoint))

    # the checkpoint of a later stage is refused
    _, answer = server.call(
        _request(the_plan, stage="6", action="checkpoint"), now=BASE, boot=BOOT_BEFORE
    )
    assert answer is not None
    assert answer["ok"] is False
    assert answer["code"] == "out_of_order"

    # the token of stage 2 is still the token of stage 2
    _, answer = server.call(
        _request(the_plan, stage="2", token=token), now=BASE, boot=BOOT_BEFORE
    )
    assert answer is not None
    assert answer["ok"] is True
    assert answer["status"] == "rebooting"


def _checkpoint_stage_two(server: Server, the_plan: dict[str, Any]) -> str:
    """Stages 0 and 1 done and the checkpoint of stage 2 taken; its id."""
    assert _complete(server, the_plan, "0")["status"] == "done"
    assert _complete(server, the_plan, "1")["status"] == "done"
    _, answer = server.call(
        _request(the_plan, stage="2", action="checkpoint"), now=BASE, boot=BOOT_BEFORE
    )
    assert answer is not None
    assert answer["status"] == "checkpointed"
    checkpoint = _checkpoint_id(server)
    assert checkpoint != ""
    return checkpoint


def test_the_helper_refuses_a_checkpoint_of_a_stage_in_flight(server: Server) -> None:
    """A stage that waits for a reboot takes no new checkpoint."""
    the_plan = _plan()
    checkpoint = _checkpoint_stage_two(server, the_plan)
    token = _token(plan.stage_digest(plan.digest(the_plan), "2", checkpoint))
    _, answer = server.call(
        _request(the_plan, stage="2", token=token), now=BASE, boot=BOOT_BEFORE
    )
    assert answer is not None
    assert answer["status"] == "rebooting"
    before = server.journal()

    _, answer = server.call(
        _request(the_plan, stage="2", action="checkpoint"), now=BASE, boot=BOOT_BEFORE
    )
    assert answer is not None
    assert answer["ok"] is False
    assert answer["code"] == "out_of_order"
    assert server.journal() == before

    # the token of the owner still completes the stage
    _, answer = server.call(
        _request(the_plan, stage="2", action="status", token=token),
        now=BASE,
        boot=BOOT_AFTER,
    )
    assert answer is not None
    assert answer["ok"] is True
    assert answer["status"] == "done"


def test_the_helper_refuses_a_second_checkpoint_of_a_stage(server: Server) -> None:
    """One checkpoint per stage per plan: the signed id is never replaced."""
    the_plan = _plan()
    checkpoint = _checkpoint_stage_two(server, the_plan)
    before = server.journal()

    _, answer = server.call(
        _request(the_plan, stage="2", action="checkpoint"), now=BASE, boot=BOOT_BEFORE
    )
    assert answer is not None
    assert answer["ok"] is False
    assert answer["code"] == "out_of_order"
    assert server.journal() == before

    token = _token(plan.stage_digest(plan.digest(the_plan), "2", checkpoint))
    _, answer = server.call(
        _request(the_plan, stage="2", token=token), now=BASE, boot=BOOT_BEFORE
    )
    assert answer is not None
    assert answer["ok"] is True
    assert answer["status"] == "rebooting"


def _complete_with_checkpoint(
    server: Server, the_plan: dict[str, Any], stage: str
) -> dict[str, Any]:
    """Take the checkpoint of an irreversible stage, then run it with
    the token of its stage digest."""
    _, answer = server.call(
        _request(the_plan, stage=stage, action="checkpoint"), now=BASE, boot=BOOT_BEFORE
    )
    assert answer is not None
    assert answer["ok"] is True, answer
    checkpoint = _checkpoint_id(server)
    token = _token(plan.stage_digest(plan.digest(the_plan), stage, checkpoint))
    return _complete(server, the_plan, stage, token=token)


def _run_up_to_stage_nine(server: Server, the_plan: dict[str, Any]) -> None:
    """Run the graph of DC1 up to stage 9: every stage before it done."""
    for stage in ("0", "1", "2", "3", "4", "5", "6", "7", "8"):
        if plan.STAGE_KINDS[stage] == "irreversible":
            answer = _complete_with_checkpoint(server, the_plan, stage)
        else:
            answer = _complete(server, the_plan, stage)
        assert answer["status"] == "done", (stage, answer)


def test_the_plan_token_opens_stage_nine_in_its_turn(server: Server) -> None:
    """Stage 9 is covered by the plan token (the maintainer, 2026-11-13)."""
    the_plan = _plan()
    _run_up_to_stage_nine(server, the_plan)

    answer = _complete(server, the_plan, "9")
    assert answer["ok"] is True
    assert answer["status"] == "done"
    assert server.journal()[-1]["stage"] == "9"
    assert server.journal()[-1]["state"] == "done"


def test_the_helper_refuses_a_stage_token_for_stage_nine(server: Server) -> None:
    """Stage 9 is never opened by a stage token, whatever its checkpoint."""
    the_plan = _plan()
    digest = plan.digest(the_plan)
    _run_up_to_stage_nine(server, the_plan)
    before = server.names()

    checkpoint = _checkpoint_id(server)
    assert checkpoint != ""
    token = _token(plan.stage_digest(digest, "9", checkpoint))
    _, answer = server.call(
        _request(the_plan, stage="9", token=token), now=BASE, boot=BOOT_BEFORE
    )
    assert answer is not None
    assert answer["ok"] is False
    assert answer["code"] == "bad_token"
    assert server.names() == before


def test_the_helper_refuses_stage_nine_out_of_order(server: Server) -> None:
    """The plan token opens stage 9 only when it is next in the graph."""
    the_plan = _plan()
    result, answer = server.call(_request(the_plan, stage="9"), now=BASE, boot=BOOT_BEFORE)
    assert answer is not None
    assert answer["ok"] is False
    assert answer["code"] == "out_of_order"
    assert server.journal() == []
    assert result.returncode == 0

    # and with stage 8 not done yet
    for stage in ("0", "1"):
        assert _complete(server, the_plan, stage)["status"] == "done"
    _, answer = server.call(_request(the_plan, stage="9"), now=BASE, boot=BOOT_BEFORE)
    assert answer is not None
    assert answer["ok"] is False
    assert answer["code"] == "out_of_order"


def test_the_helper_takes_no_checkpoint_of_stage_nine(server: Server) -> None:
    """Stage 9 takes no checkpoint: it is not an irreversible stage."""
    the_plan = _plan()
    _run_up_to_stage_nine(server, the_plan)
    before = server.names()
    _, answer = server.call(
        _request(the_plan, stage="9", action="checkpoint"), now=BASE, boot=BOOT_BEFORE
    )
    assert answer is not None
    assert answer["ok"] is False
    assert answer["code"] == "out_of_order"
    assert server.names() == before


def test_the_helper_refuses_stage_nine_relabelled_by_the_plan(server: Server) -> None:
    """The kind of stage 9 is the kind of the design, whatever the plan
    bytes say of it."""
    the_plan = _plan()
    original = _canonical(the_plan)
    assert b"stages.kind.9=final\n" in original
    changed = original.replace(b"stages.kind.9=final\n", b"stages.kind.9=read\n")
    assert changed != original

    request = _request(the_plan, stage="9")
    request["plan"] = base64.b64encode(changed).decode("ascii")
    request["token"] = _token(hashlib.sha256(changed).hexdigest())
    _, answer = server.call(request, now=BASE, boot=BOOT_BEFORE)
    assert answer is not None
    assert answer["ok"] is False
    assert answer["code"] == "schema"
    assert server.journal() == []


def test_the_helper_refuses_a_plan_whose_kinds_differ_from_the_design(
    server: Server,
) -> None:
    """The kinds of the plan are the kinds of the design."""
    the_plan = _plan()
    original = _canonical(the_plan)
    assert b"stages.kind.2=irreversible\n" in original
    changed = original.replace(
        b"stages.kind.2=irreversible\n", b"stages.kind.2=reversible\n"
    )
    assert changed != original

    request = _request(the_plan)
    request["plan"] = base64.b64encode(changed).decode("ascii")
    request["token"] = _token(hashlib.sha256(changed).hexdigest())
    _, answer = server.call(request, now=BASE, boot=BOOT_BEFORE)
    assert answer is not None
    assert answer["ok"] is False
    assert answer["code"] == "schema"
    assert server.journal() == []


# ---------------------------------------------------------------------------
# the reboot of a stage
# ---------------------------------------------------------------------------


def test_the_status_keeps_the_stage_rebooting_until_the_boot_time_advances(
    server: Server,
) -> None:
    """A status before the reboot answers rebooting and writes nothing."""
    the_plan = _plan()
    answer = _complete(server, the_plan, "0")
    assert answer["status"] == "done"

    request = _request(the_plan, stage="1")
    _, answer = server.call(request, now=BASE, boot=BOOT_BEFORE)
    assert answer is not None
    assert answer["ok"] is True
    assert answer["status"] == "rebooting"
    entries = server.journal()
    assert entries[-1]["state"] == "rebooting"

    before = len(server.journal())
    _, answer = server.call(
        _request(the_plan, stage="1", action="status"), now=BASE, boot=BOOT_BEFORE
    )
    assert answer is not None
    assert answer["ok"] is True
    assert answer["status"] == "rebooting"
    assert len(server.journal()) == before

    _, answer = server.call(
        _request(the_plan, stage="1", action="status"), now=BASE, boot=BOOT_AFTER
    )
    assert answer is not None
    assert answer["ok"] is True
    assert answer["status"] == "done"
    assert server.journal()[-1]["state"] == "done"


def test_the_post_boot_completion_is_allowed_until_the_expiry_plus_fifteen_minutes(
    server: Server,
) -> None:
    """A stage that reboots may be completed until its EXP plus 15 minutes."""
    the_plan = _plan()
    answer = _complete(server, the_plan, "0")
    assert answer["status"] == "done"

    _, answer = server.call(
        _request(the_plan, stage="1"), now=BASE, boot=BOOT_BEFORE
    )
    assert answer is not None
    assert answer["status"] == "rebooting"

    # one minute before the end of the grace: the stage completes
    _, answer = server.call(
        _request(the_plan, stage="1", action="status"),
        now=EXP + 899,
        boot=BOOT_AFTER,
    )
    assert answer is not None
    assert answer["ok"] is True
    assert answer["status"] == "done"


def test_the_post_boot_completion_past_the_grace_stops_the_stage(server: Server) -> None:
    """Past the grace the stage is stopped and needs a new token."""
    the_plan = _plan()
    answer = _complete(server, the_plan, "0")
    assert answer["status"] == "done"

    _, answer = server.call(
        _request(the_plan, stage="1"), now=BASE, boot=BOOT_BEFORE
    )
    assert answer is not None
    assert answer["status"] == "rebooting"

    _, answer = server.call(
        _request(the_plan, stage="1", action="status"),
        now=EXP + 901,
        boot=BOOT_AFTER,
    )
    assert answer is not None
    assert answer["ok"] is False
    assert answer["code"] == "expired"
    entries = server.journal()
    assert entries[-1]["state"] == "stopped"
    assert entries[-1]["reason"] == "grace_passed"


def test_a_reboot_that_never_returns_stops_the_stage_after_the_grace(
    server: Server,
) -> None:
    """A stage whose server never comes back is stopped after the grace."""
    the_plan = _plan()
    answer = _complete(server, the_plan, "0")
    assert answer["status"] == "done"

    _, answer = server.call(
        _request(the_plan, stage="1"), now=BASE, boot=BOOT_BEFORE
    )
    assert answer is not None
    assert answer["status"] == "rebooting"

    # the boot time never advances: the stage waits and waits
    _, answer = server.call(
        _request(the_plan, stage="1", action="status"),
        now=EXP + 901,
        boot=BOOT_BEFORE,
    )
    assert answer is not None
    assert answer["ok"] is False
    assert answer["code"] == "expired"
    entries = server.journal()
    assert entries[-1]["state"] == "stopped"
    assert entries[-1]["reason"] == "grace_passed"


# ---------------------------------------------------------------------------
# the journal
# ---------------------------------------------------------------------------


def test_the_journal_entry_holds_the_fields_of_the_design(server: Server) -> None:
    """Every entry holds the stage, the state, the digest, the checkpoint
    id and the boot time."""
    the_plan = _plan()
    _, answer = server.call(_request(the_plan), now=BASE, boot=BOOT_BEFORE)
    assert answer is not None
    assert answer["ok"] is True

    entries = server.journal()
    assert len(entries) == 2
    for entry in entries:
        assert set(entry) >= {
            "stage",
            "state",
            "digest",
            "checkpoint",
            "boot",
        }
        assert entry["stage"] == "0"
        assert entry["digest"] == plan.digest(the_plan)
        assert entry["boot"] == "2026-11-12T00:00:00.0000000Z"
    assert entries[0]["state"] == "started"
    assert entries[1]["state"] == "done"
    assert [entry["seq"] for entry in entries] == [0, 1]
    assert server.names() == [f"{RUN}.0.json", f"{RUN}.1.json"]


def test_the_helper_runs_a_stage_once_under_concurrent_requests(server: Server) -> None:
    """Two requests for one stage at once: the stage runs once."""

    def call(_: int) -> dict[str, Any] | None:
        the_plan = _plan()
        _, answer = server.call(_request(the_plan), now=BASE, boot=BOOT_BEFORE)
        return answer

    with ThreadPoolExecutor(max_workers=4) as pool:
        answers = list(pool.map(call, range(4)))

    assert all(answer is not None for answer in answers)
    done = [answer for answer in answers if answer["ok"] and answer["status"] == "done"]
    assert len(done) == 1
    for answer in answers:
        if answer is done[0]:
            continue
        assert answer["ok"] is False
        # a request that finds the lock of the journal of the server held
        # is refused journal_busy (the lab run of 2026-11-23), and one that
        # finds the stage done is refused already_done.
        assert answer["code"] in {"journal_busy", "already_done"}
    entries = server.journal()
    assert [entry["state"] for entry in entries] == ["started", "done"]


def test_the_journal_never_overwrites_an_entry(tmp_path: Path) -> None:
    """Every entry is a new file: the journal is append-only."""
    one = Server(tmp_path / "install")
    one.write_table(STAGE_TABLE)
    the_plan = _plan()

    # an entry of the run is already there
    directory = one.root / "journal"
    directory.mkdir(parents=True)
    stray = {
        "run": RUN,
        "seq": 2,
        "stage": "1",
        "state": "started",
        "digest": plan.digest(the_plan),
        "checkpoint": "",
        "boot": "2026-11-12T00:00:00.0000000Z",
        "time": BASE,
        "checks": [],
    }
    (directory / f"{RUN}.2.json").write_text(json.dumps(stray), encoding="utf-8")

    _, answer = one.call(_request(the_plan), now=BASE, boot=BOOT_BEFORE)
    assert answer is not None
    assert answer["ok"] is True

    # the entries of the run go on after the one that is there, and the
    # one that is there is untouched
    assert one.names() == [f"{RUN}.2.json", f"{RUN}.3.json", f"{RUN}.4.json"]
    assert json.loads((directory / f"{RUN}.2.json").read_text(encoding="utf-8")) == stray


def test_a_foreign_file_in_the_journal_does_not_stop_the_run(server: Server) -> None:
    """A .json file that is not named <run>.<seq>.json is not an entry."""
    the_plan = _plan()
    assert _complete(server, the_plan, "0")["status"] == "done"
    (server.root / "journal" / "notes.json").write_text("{}", encoding="utf-8")

    _, answer = server.call(_request(the_plan, stage="1"), now=BASE, boot=BOOT_BEFORE)
    assert answer is not None
    assert answer["ok"] is True
    assert answer["status"] == "rebooting"


def test_the_terminal_entry_of_the_task_survives_a_dropped_connection(
    tmp_path: Path,
) -> None:
    """The task writes the terminal entry, so a dropped connection loses nothing."""
    table = copy.deepcopy(STAGE_TABLE)
    table["0"]["drop"] = True
    one = Server(tmp_path / "install")
    one.write_table(table)

    the_plan = _plan()
    result, answer = one.call(_request(the_plan), now=BASE, boot=BOOT_BEFORE)
    assert answer is None
    assert result.stdout.strip() == ""
    assert result.returncode != 0

    entries = one.journal()
    assert entries[-1]["state"] == "done"
    assert entries[-1]["stage"] == "0"

    _, answer = one.call(
        _request(the_plan, action="status"), now=BASE, boot=BOOT_BEFORE
    )
    assert answer is not None
    assert answer["ok"] is True
    assert answer["status"] == "done"


def test_the_helper_ignores_a_stage_table_in_the_install_root(tmp_path: Path) -> None:
    """A stage table in the install root is not the table of the helper.

    With no table named on the command line the helper has no stage
    templates yet (tasks 5 to 8), so it runs nothing and writes nothing.
    """
    one = Server(tmp_path / "install")
    table = copy.deepcopy(STAGE_TABLE)
    table["0"]["drop"] = True
    one.write_table(table)

    the_plan = _plan()
    result, answer = one.call(
        _request(the_plan), now=BASE, boot=BOOT_BEFORE, table=None
    )
    assert answer is not None
    assert answer["ok"] is False
    assert answer["code"] == "schema"
    assert result.returncode == 0
    assert one.journal() == []


# ---------------------------------------------------------------------------
# the key of the server
# ---------------------------------------------------------------------------


def test_the_helper_uses_the_key_of_the_server(tmp_path: Path) -> None:
    """The key of the server is the one the bootstrap derives."""
    key = derive_k(b"the passphrase of the owner", "build1")
    one = Server(tmp_path / "install", key_hex=key)
    one.write_table(STAGE_TABLE)

    the_plan = _plan()
    request = _request(the_plan, token=_token(plan.digest(the_plan), key=key))
    _, answer = one.call(request, now=BASE, boot=BOOT_BEFORE)
    assert answer is not None
    assert answer["ok"] is True

    # the key of another server does not open it
    other = Server(tmp_path / "other", key_hex="c3" * 32)
    other.write_table(STAGE_TABLE)
    request = _request(the_plan)
    _, answer = other.call(request, now=BASE, boot=BOOT_BEFORE)
    assert answer is not None
    assert answer["ok"] is False
    assert answer["code"] == "bad_token"


def test_the_helper_refuses_an_override_over_ssh(server: Server) -> None:
    """The forced command takes no argument from the client."""
    the_plan = _plan()
    _, answer = server.call(
        _request(the_plan),
        now=BASE,
        boot=BOOT_BEFORE,
        env={"SSH_CONNECTION": "192.0.2.9 5000 192.0.2.11 22"},
    )
    assert answer is not None
    assert answer["ok"] is False
    assert answer["code"] == "schema"


def _checkpoint_id(server: Server) -> str:
    """The id of the checkpoint the helper took, out of its journal."""
    for entry in reversed(server.journal()):
        if entry["state"] == "checkpointed":
            return str(entry["checkpoint"])
    return ""


def _leave_started(server: Server, the_plan: dict[str, Any], stage: str) -> None:
    """The helper died after the entry of the start of ``stage``: the
    journal holds that entry and no terminal one."""
    seq = len(server.journal())
    started = {
        "run": RUN,
        "seq": seq,
        "stage": stage,
        "state": "started",
        "reason": "",
        "digest": plan.digest(the_plan),
        "checkpoint": "",
        "boot": "2026-11-12T00:00:00.0000000Z",
        "time": BASE,
        "checks": [],
    }
    (server.root / "journal" / f"{RUN}.{seq}.json").write_text(
        json.dumps(started), encoding="utf-8"
    )


def test_the_helper_resumes_an_irreversible_stage_left_started(server: Server) -> None:
    """A resume plan checkpoints an irreversible stage left started, then runs it."""
    the_plan = _plan()
    assert _complete(server, the_plan, "0")["status"] == "done"
    assert _complete(server, the_plan, "1")["status"] == "done"
    _leave_started(server, the_plan, "2")

    resumed = _resume_plan(the_plan, "2")
    result, answer = server.call(
        _request(resumed, stage="2", action="checkpoint"), now=BASE, boot=BOOT_BEFORE
    )
    assert answer is not None, result.stderr
    assert answer["ok"] is True, result.stderr
    assert answer["status"] == "checkpointed"
    checkpoint = _checkpoint_id(server)
    assert server.journal()[-1]["digest"] == plan.digest(resumed)

    token = _token(plan.stage_digest(plan.digest(resumed), "2", checkpoint))
    result, answer = server.call(
        _request(resumed, stage="2", token=token), now=BASE, boot=BOOT_BEFORE
    )
    assert answer is not None
    assert answer["ok"] is True, result.stderr
    assert answer["status"] == "rebooting"
    assert server.journal()[-1]["digest"] == plan.digest(resumed)


def test_the_helper_refuses_a_checkpoint_of_a_stage_left_started_under_its_own_plan(
    server: Server,
) -> None:
    """Only a resume plan checkpoints a stage left started; the plan of the run does not."""
    the_plan = _plan()
    assert _complete(server, the_plan, "0")["status"] == "done"
    assert _complete(server, the_plan, "1")["status"] == "done"
    _leave_started(server, the_plan, "2")
    before = server.journal()

    result, answer = server.call(
        _request(the_plan, stage="2", action="checkpoint"), now=BASE, boot=BOOT_BEFORE
    )
    assert answer is not None
    assert answer["ok"] is False
    assert answer["code"] == "out_of_order"
    assert "in flight" in result.stderr
    assert server.journal() == before


def test_a_resume_plan_takes_no_checkpoint_of_a_stage_that_waits_for_a_reboot(
    server: Server,
) -> None:
    """A stage that waits for a reboot takes no checkpoint, under a resume plan too."""
    the_plan = _plan()
    checkpoint = _checkpoint_stage_two(server, the_plan)
    token = _token(plan.stage_digest(plan.digest(the_plan), "2", checkpoint))
    _, answer = server.call(
        _request(the_plan, stage="2", token=token), now=BASE, boot=BOOT_BEFORE
    )
    assert answer is not None
    assert answer["status"] == "rebooting"
    before = server.journal()

    resumed = _resume_plan(the_plan, "2")
    _, answer = server.call(
        _request(resumed, stage="2", action="checkpoint"), now=BASE, boot=BOOT_BEFORE
    )
    assert answer is not None
    assert answer["ok"] is False
    assert answer["code"] == "out_of_order"
    assert server.journal() == before


def test_the_status_completes_nothing_on_a_server_with_no_stage_templates(
    server: Server,
) -> None:
    """After the boot, a server with no stage table answers schema and writes no done."""
    the_plan = _plan()
    assert _complete(server, the_plan, "0")["status"] == "done"
    _, answer = server.call(_request(the_plan, stage="1"), now=BASE, boot=BOOT_BEFORE)
    assert answer is not None
    assert answer["status"] == "rebooting"
    before = server.journal()

    result, answer = server.call(
        _request(the_plan, stage="1", action="status"),
        now=BASE,
        boot=BOOT_AFTER,
        table=None,
    )
    assert answer is not None
    assert answer["ok"] is False
    assert answer["code"] == "schema"
    assert "not built yet" in result.stderr
    assert server.journal() == before
    assert all(entry["state"] != "done" for entry in before if entry["stage"] == "1")


# ---------------------------------------------------------------------------
# the lock of the journal of the server (the lab run of 2026-11-23)
# ---------------------------------------------------------------------------

#: The driver of a request while another request holds the lock of the
#: journal of the server: the lock file is open with no sharing, so the
#: helper cannot take it.
LOCK_DRIVER = r"""
param([string]$Helper, [string]$InstallRoot, [string]$RequestPath, [string]$OutPath)
$ErrorActionPreference = 'Stop'
. $Helper -InstallRoot $InstallRoot
$journal = Join-Path $InstallRoot 'journal'
if (-not (Test-Path -LiteralPath $journal)) { $null = New-Item -ItemType Directory -Path $journal -Force }
$held = [System.IO.File]::Open((Join-Path $journal 'lock'), [System.IO.FileMode]::OpenOrCreate,
    [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
$response = $null
try {
    $request = ConvertFrom-NewtonRequest ([System.IO.File]::ReadAllText($RequestPath))
    $response = Invoke-NewtonAction -Request $request
} catch {
    $response = New-NewtonAnswer -Ok $false -Status 'refused' `
        -Code (Get-NewtonRefusalCode $_) -Checks @()
} finally {
    $held.Close()
    Exit-NewtonJournalLock
}
[System.IO.File]::WriteAllText($OutPath, ($response | ConvertTo-Json -Depth 8 -Compress))
"""


def _call_while_the_lock_is_held(server: Server, request: dict[str, Any], tmp_path: Path) -> dict[str, Any]:
    """One request to the helper while another request holds the lock of
    the journal of the server."""
    driver = tmp_path / "lock-driver.ps1"
    driver.write_text(LOCK_DRIVER, encoding="utf-8")
    request_path = tmp_path / "request.json"
    request_path.write_text(json.dumps(request), encoding="utf-8")
    out_path = tmp_path / "answer.json"
    result = subprocess.run(
        [
            str(PWSH),
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(driver),
            "-Helper",
            str(HELPER),
            "-InstallRoot",
            str(server.root),
            "-RequestPath",
            str(request_path),
            "-OutPath",
            str(out_path),
        ],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert out_path.is_file(), result.stdout + result.stderr
    answer = json.loads(out_path.read_text(encoding="utf-8-sig"))
    assert isinstance(answer, dict)
    return answer


def test_a_request_while_another_holds_the_journal_lock_is_refused_journal_busy(
    server: Server, tmp_path: Path
) -> None:
    """One request at a time: a second one finds the lock of the journal of
    the server held, and the helper says so with its own code
    ``journal_busy`` (the lab run of 2026-11-23 measured the refusal)."""
    the_plan = _plan()
    answer = _call_while_the_lock_is_held(server, _request(the_plan, stage="0", action="status"), tmp_path)
    assert (answer["ok"], answer["status"], answer["code"]) == (False, "refused", "journal_busy"), answer
    assert answer["checks"] == []
    # nothing was written: the request never got the lock
    assert server.journal() == []
    assert server.names() == []


def test_the_journal_busy_code_is_one_of_the_codes_of_the_build(server: Server) -> None:
    """The code the helper answers with is one the approval and the runner
    know."""
    from newton_mcp import approve

    assert "journal_busy" in approve.BUILD_REFUSAL_CODES
