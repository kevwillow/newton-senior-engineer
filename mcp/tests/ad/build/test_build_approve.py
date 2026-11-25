"""The approval of an AD build (PLAN-1.5 task 2, DESIGN-1.5 "The plan",
"Tokens", "Secrets", "Checkpoints").

Every constant of this file comes from the two documents and from nowhere
else: the six-hour window of the plan token, the thirty-minute window of
a stage token, the stage digest of ``newton_mcp.ad.build.plan``, the two
info strings of the derived secrets, the stage ids of the design and the
two kinds of checkpoint.

The plan approval prints every field of the plan, derives the key of every
server from the one passphrase, shows the DSRM and the admin password once
in the terminal and writes one plan token per server.  A passphrase that no
fingerprint on record confirms is asked twice.  The stage approval verifies
the checkpoint itself through the adapter -- never through the runner's own
word -- and writes one stage token per server over the stage digest of the
verified checkpoint.  It never mints a token for a plan the owner did not
approve.
"""

from __future__ import annotations

import copy
import io
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from newton_mcp import approve
from newton_mcp.ad.build import checkpoint as build_checkpoint
from newton_mcp.ad.build import plan
from ops_fixture import OPS  # type: ignore[import-not-found]


#: The passphrase of the owner in the tests.
PASSPHRASE = "correct horse battery staple"

#: The instant the approvals of the tests are made at.
NOW = datetime(2027, 1, 1, tzinfo=timezone.utc)

#: The plan id of the tests: 32 lowercase hexadecimal characters.
PLAN_ID = "0123456789abcdef0123456789abcdef"

#: The window of the plan token: six hours (PLAN-1.5, Constraints).
PLAN_WINDOW_S = 6 * 60 * 60

#: The window of a stage token: thirty minutes (PLAN-1.5, Constraints).
STAGE_WINDOW_S = 30 * 60

#: The id of the checkpoint of the tests.
CHECKPOINT_ID = "3f2b1c4d-5e6f-4a8b-9c0d-1e2f3a4b5c6d"

#: The name of the checkpoint of the tests.
CHECKPOINT_NAME = "m-hvcp-1"

#: The plan of the tests: two servers, one baseline option, one finding.
#: Every value is synthetic (RFC 5737 addresses).
INPUTS: dict[str, Any] = {
    "domain": {
        "dns_name": "ad-build.test",
        "netbios": "ADBUILD",
        "functional_level": "Win2025",
        "site": "Default-First-Site-Name",
        "ou_tree": ["IT/Servers", "IT/Workstations"],
        "groups": ["IT Admins", "IT Operators"],
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
            "checkpoint": "proxmox",
            "vmgenid": "44387c6b-1f2e-4a5b-8c9d-0e1f2a3b4c5d",
            "agent": 1,
        },
    ],
    "baseline": {
        "version": "2026.11",
        "options": {"administrator": "random-password"},
    },
    "accepted_findings": [
        {"id": "AD-A-51", "reason": "owner-accepted"},
    ],
    "ops": dict(OPS),
}


class FakeVerifier:
    """The fake of the checkpoint adapter of task 7.

    The real adapters are task 7; the approval only knows the shape of
    one: ``verify(server_cfg, cp, kind, *, stage) -> bool`` (the stage is
    passed by keyword, the maintainer, 2026-11-13).  The fake records the calls, so
    a test can see that the approval asked the adapter itself and not
    the runner's state file.
    """

    def __init__(self, *, ok: bool = True) -> None:
        self.ok = ok
        self.calls: list[tuple[dict[str, Any], dict[str, Any], str]] = []
        self.stages: list[str] = []
        self.bounds: list[int] = []

    def verify(
        self,
        server_cfg: dict[str, Any],
        cp: dict[str, Any],
        kind: str,
        *,
        stage: str,
        not_before: int,
    ) -> bool:
        self.calls.append((dict(server_cfg), dict(cp), kind))
        self.stages.append(stage)
        self.bounds.append(not_before)
        return self.ok


class WbadminVerifier:
    """A test double of the wbadmin stage rule, in the approval's own
    ``verify(server_cfg, cp, kind, *, stage)`` shape.

    It reads the "Can recover" items of the checkpoint through ``read``
    and applies ``wbadmin_version_verifies``, nothing else.  It was the
    product's ``WbadminVerifier`` until the task 7 triage (m2): it has no
    genid read, no time bound and no computer check, so it lives here and
    nothing in ``newton_mcp`` holds it.
    """

    def __init__(self, read: Any) -> None:
        self._read = read

    def verify(
        self,
        server_cfg: dict[str, Any],
        cp: dict[str, Any],
        kind: str,
        *,
        stage: str,
        not_before: int,
    ) -> bool:
        if server_cfg.get("checkpoint") != "wbadmin" or kind not in build_checkpoint.CHECKPOINT_KINDS:
            return False
        return build_checkpoint.wbadmin_version_verifies(self._read(server_cfg, cp), stage=stage)


class RaisingVerifier:
    """An adapter that cannot answer."""

    def verify(
        self,
        server_cfg: dict[str, Any],
        cp: dict[str, Any],
        kind: str,
        *,
        stage: str,
        not_before: int,
    ) -> bool:
        raise RuntimeError("the adapter cannot answer")


@pytest.fixture(autouse=True)
def state_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """The state directory of the test."""
    root = tmp_path / "state"
    monkeypatch.setenv("NEWTON_STATE_DIR", str(root))
    return root


@pytest.fixture
def built_plan() -> dict[str, Any]:
    """The plan of the tests, built fresh."""
    return plan.plan_build(copy.deepcopy(INPUTS))


@pytest.fixture
def stored_plan(
    state_dir: Path, built_plan: dict[str, Any]
) -> Path:
    """The plan of the tests, written in the state directory."""
    path = state_dir / "ad-build-plans" / f"{PLAN_ID}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(built_plan), encoding="utf-8")
    return path


def _approval_path(plan_id: str = PLAN_ID) -> Path:
    """The path of the plan approval of the tests."""
    return approve.build_plan_dir() / f"{plan_id}.approval.json"


def _stage_approval_path(stage: str, plan_id: str = PLAN_ID) -> Path:
    """The path of the stage approval of the tests."""
    return approve.build_plan_dir() / f"{plan_id}.stage-{stage}.approval.json"


def _key(device: str, passphrase: str = PASSPHRASE) -> str:
    """The key of one server of the tests."""
    return approve.derive_k(passphrase.encode("utf-8"), device)


def _approve_build(
    monkeypatch: pytest.MonkeyPatch,
    plan_id: str = PLAN_ID,
    *,
    passphrase: str = PASSPHRASE,
    confirmation: str | None = None,
) -> int:
    """Run the plan approval with a fixed terminal."""
    if confirmation is None:
        confirmation = f"approve {plan_id[:8]}"
    monkeypatch.setattr(approve, "_getpass", lambda prompt: passphrase, raising=True)
    monkeypatch.setattr("sys.stdin", io.StringIO(confirmation + "\n"), raising=True)
    return approve.approve_ad_build(plan_id, now=NOW)


#: The recorded completion the default journal of the tests gives every
#: stage: an hour before the approvals (task 8 reads it through the
#: helper transport).
JOURNAL_DONE_AT = int(NOW.timestamp()) - 3600


class JournalTransport:
    """The helper transport of the tests: a status of stage 0 under the
    plan token answers the recorded completion of every stage (task 8).
    The requests are recorded."""

    def __init__(self, completed: dict[str, Any] | None = None, *, answer: Any = None, fail: bool = False) -> None:
        self.completed = {stage: JOURNAL_DONE_AT for stage in plan.STAGE_IDS} if completed is None else completed
        self.answer = answer
        self.fail = fail
        self.requests: list[tuple[str, dict[str, Any]]] = []

    def send(self, device: str, request: dict[str, Any]) -> dict[str, Any]:
        from newton_mcp.ad.build.transport import HelperUnavailable

        self.requests.append((device, dict(request)))
        if self.fail:
            raise HelperUnavailable("the build helper did not answer")
        if self.answer is not None:
            return self.answer
        return {"ok": True, "status": "done", "code": "", "checks": [], "completed": dict(self.completed)}


def _approve_stage(
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
    *,
    transport: Any = None,
    verifier: Any = None,
    plan_id: str = PLAN_ID,
    passphrase: str = PASSPHRASE,
    confirmation: str | None = None,
    now: datetime = NOW,
) -> int:
    """Run the stage approval with a fixed terminal."""
    if confirmation is None:
        confirmation = f"approve stage {stage} of {plan_id[:8]}"
    monkeypatch.setattr(approve, "_getpass", lambda prompt: passphrase, raising=True)
    monkeypatch.setattr("sys.stdin", io.StringIO(confirmation + "\n"), raising=True)
    if verifier is None:
        verifier = FakeVerifier()
    if transport is None:
        transport = JournalTransport()
    return approve.approve_ad_build_stage(
        plan_id, stage, verifier=verifier, transport=transport, now=now
    )


def _write_run_state(
    state_dir: Path,
    built_plan: dict[str, Any],
    *,
    stage: str = "2",
    plan_digest: str | None = None,
    servers: dict[str, Any] | None = None,
) -> Path:
    """Write the runner's state of one build, as the runner writes it."""
    if plan_digest is None:
        plan_digest = plan.digest(built_plan)
    if servers is None:
        servers = {
            "build1": {
                "stage": stage,
                "state": "stopped_for_approval",
                "checkpoint": {"name": CHECKPOINT_NAME, "id": CHECKPOINT_ID},
                "checkpoint_kind": "workgroup",
            },
        }
    record = {
        "plan_id": PLAN_ID,
        "plan_digest": plan_digest,
        "state": "stopped_for_approval",
        "stage": stage,
        "servers": servers,
    }
    path = state_dir / "ad-build-plans" / f"{PLAN_ID}.run.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record), encoding="utf-8")
    return path


def _leaf_lines(value: Any, key: str = "") -> list[str]:
    """Every leaf of the plan, as the whole line the terminal shows it.

    A leaf is a value under its own name: the line of the terminal is
    the name, a colon and the value, whatever the section it is in.
    """
    if isinstance(value, dict):
        found: list[str] = []
        for name, item in value.items():
            found.extend(_leaf_lines(item, str(name)))
        return found
    if isinstance(value, list):
        if value and all(isinstance(item, dict) for item in value):
            found = []
            for item in value:
                found.extend(_leaf_lines(item, key))
            return found
        return [f"{key}: {', '.join(str(item) for item in value)}"]
    return [f"{key}: {value}"]


def _server_blocks(out: str) -> list[list[str]]:
    """The block of every server, as the terminal shows it."""
    blocks: list[list[str]] = []
    for line in out.splitlines():
        stripped = line.strip()
        if stripped.startswith("Server ") and stripped.endswith(":"):
            blocks.append([])
            continue
        if blocks:
            blocks[-1].append(stripped)
    return blocks


def _write_setup_fingerprint(device: str, passphrase: str) -> Path:
    """Write the fingerprint of the setup of one server, as the setup does."""
    path = approve.state_dir() / "approval-fp" / device
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text(
        f"v1 {approve.approval_fingerprint(_key(device, passphrase))}\n",
        encoding="ascii",
    )
    return path


# --------------------------------------------------------------------------
# The plan approval
# --------------------------------------------------------------------------


def test_the_plan_approval_prints_every_field_of_the_plan(
    stored_plan: Path,
    built_plan: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The owner sees every field of the plan they approve.

    Every leaf is a whole line of its own: a field that is skipped is
    a line that is not there, and the value of one field cannot stand
    in for the value of another.
    """
    assert _approve_build(monkeypatch) == 0

    out = capsys.readouterr().out
    lines = {line.strip() for line in out.splitlines()}
    for expected in _leaf_lines(built_plan):
        assert expected in lines, expected

    blocks = _server_blocks(out)
    assert len(blocks) == len(built_plan["servers"])
    for server, block in zip(built_plan["servers"], blocks):
        block_lines = set(block)
        for expected in _leaf_lines(server):
            assert expected in block_lines, expected


def test_the_plan_approval_writes_one_token_per_server(
    stored_plan: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One token per server: every server has its own key."""
    assert _approve_build(monkeypatch) == 0

    record = json.loads(_approval_path().read_text(encoding="utf-8"))
    assert set(record["tokens"]) == {"build1", "build2"}


def test_the_token_of_a_server_verifies_only_with_its_own_key(
    stored_plan: Path,
    built_plan: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A token of one server does not open the other server."""
    assert _approve_build(monkeypatch) == 0

    record = json.loads(_approval_path().read_text(encoding="utf-8"))
    digest = plan.digest(built_plan)
    nbf = record["nbf"]
    exp = record["exp"]
    first = _key("build1")
    second = _key("build2")

    assert record["tokens"]["build1"] == approve.approval_token(
        first, digest, nbf, exp
    )
    assert record["tokens"]["build2"] == approve.approval_token(
        second, digest, nbf, exp
    )
    assert record["tokens"]["build1"] != approve.approval_token(
        second, digest, nbf, exp
    )
    assert record["tokens"]["build2"] != approve.approval_token(
        first, digest, nbf, exp
    )


def test_the_plan_token_covers_the_plan_digest(
    stored_plan: Path,
    built_plan: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The plan token is over the digest of the canonical bytes."""
    assert _approve_build(monkeypatch) == 0

    record = json.loads(_approval_path().read_text(encoding="utf-8"))
    assert record["plan_digest"] == plan.digest(built_plan)


def test_the_plan_token_window_is_six_hours(
    stored_plan: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The plan token is good for six hours (PLAN-1.5, Constraints)."""
    assert _approve_build(monkeypatch) == 0

    record = json.loads(_approval_path().read_text(encoding="utf-8"))
    assert record["nbf"] == int(NOW.timestamp())
    assert record["exp"] - record["nbf"] == PLAN_WINDOW_S


def test_an_edited_plan_changes_the_digest_of_the_token(
    stored_plan: Path,
    built_plan: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The digest is computed here, never read from the plan file.

    A plan file whose field was changed is another plan, and its token
    is over the digest of the plan that was approved.
    """
    assert _approve_build(monkeypatch) == 0

    record = json.loads(_approval_path().read_text(encoding="utf-8"))
    edited = copy.deepcopy(built_plan)
    edited["domain"]["site"] = "Second-Site-Name"
    stored_plan.write_text(json.dumps(edited), encoding="utf-8")
    assert _approve_build(monkeypatch) == 0

    second = json.loads(_approval_path().read_text(encoding="utf-8"))
    assert second["plan_digest"] == plan.digest(edited)
    assert second["plan_digest"] != record["plan_digest"]


def test_the_passwords_are_shown_in_the_terminal(
    stored_plan: Path,
    built_plan: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The DSRM and the admin password are shown once, here."""
    assert _approve_build(monkeypatch) == 0

    out = capsys.readouterr().out
    digest = plan.digest(built_plan)
    key = _key("build1")
    assert plan.derive_secret(key, digest, plan.DSRM_INFO) in out
    assert plan.derive_secret(key, digest, plan.ADMIN_INFO) in out


def _password_after(out: str, label: str) -> str:
    """The password printed on the line after the one label."""
    lines = out.splitlines()
    found = [index for index, line in enumerate(lines) if label in line]
    assert len(found) == 1, (label, out)
    return lines[found[0] + 1].strip()


def test_each_dcs_dsrm_password_is_shown_from_its_own_key(
    stored_plan: Path,
    built_plan: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Review finding 3 of task 8 part E: DC2's helper installs a DSRM
    password derived from DC2's own K (build.ps1, the stage 7 join), so the
    approval shows that one too, under DC2's device, beside DC1's."""
    assert _approve_build(monkeypatch) == 0

    out = capsys.readouterr().out
    digest = plan.digest(built_plan)
    dc1 = plan.derive_secret(_key("build1"), digest, plan.DSRM_INFO)
    dc2 = plan.derive_secret(_key("build2"), digest, plan.DSRM_INFO)
    assert dc1 != dc2
    assert _password_after(out, "DSRM password of build1 (dc1)") == dc1
    assert _password_after(out, "DSRM password of build2 (dc2)") == dc2
    assert _password_after(out, "Owner's first admin password") == plan.derive_secret(
        _key("build1"), digest, plan.ADMIN_INFO
    )


def test_a_one_dc_plan_shows_one_dsrm_password(
    state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    inputs = copy.deepcopy(INPUTS)
    del inputs["servers"][1]
    built = plan.plan_build(inputs)
    path = state_dir / "ad-build-plans" / f"{PLAN_ID}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(built), encoding="utf-8")
    assert _approve_build(monkeypatch) == 0

    out = capsys.readouterr().out
    assert out.count("DSRM password of ") == 1
    assert _password_after(out, "DSRM password of build1 (dc1)") == plan.derive_secret(
        _key("build1"), plan.digest(built), plan.DSRM_INFO
    )


def test_a_resume_plan_shows_the_passwords_of_the_builds_first_plan(
    state_dir: Path,
    built_plan: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Review finding 4 of task 8 part E (DESIGN-1.5 open point 71): a
    resume plan's own digest is not the salt.  The DCs keep the DSRM and
    the admin password the first plan installed, and the helper derives
    from the signed secrets_from, so the approval shows those and says
    they are the first plan's."""
    first = plan.digest(built_plan)
    inputs = copy.deepcopy(INPUTS)
    inputs["resume_from"] = first
    inputs["start_stage"] = "3"
    inputs["secrets_from"] = first
    resumed = plan.plan_build(inputs)
    own = plan.digest(resumed)
    assert own != first
    path = state_dir / "ad-build-plans" / f"{PLAN_ID}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(resumed), encoding="utf-8")
    assert _approve_build(monkeypatch) == 0

    out = capsys.readouterr().out
    assert _password_after(out, "DSRM password of build1 (dc1)") == plan.derive_secret(
        _key("build1"), first, plan.DSRM_INFO
    )
    assert _password_after(out, "DSRM password of build2 (dc2)") == plan.derive_secret(
        _key("build2"), first, plan.DSRM_INFO
    )
    assert _password_after(out, "Owner's first admin password") == plan.derive_secret(
        _key("build1"), first, plan.ADMIN_INFO
    )
    for device in ("build1", "build2"):
        for info in (plan.DSRM_INFO, plan.ADMIN_INFO):
            assert plan.derive_secret(_key(device), own, info) not in out
    assert f"the passwords of the build's first plan {first[:12]}" in out
    assert "shown once" not in out


def test_the_passwords_are_nowhere_in_the_state_directory(
    stored_plan: Path,
    built_plan: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The passwords are never written in the state directory."""
    assert _approve_build(monkeypatch) == 0

    digest = plan.digest(built_plan)
    key = _key("build1")
    secrets = [
        plan.derive_secret(key, digest, plan.DSRM_INFO),
        plan.derive_secret(key, digest, plan.ADMIN_INFO),
        plan.derive_secret(_key("build2"), digest, plan.DSRM_INFO),
        PASSPHRASE,
    ]
    for path in sorted(approve.state_dir().rglob("*")):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for secret in secrets:
            assert secret not in text, path


def test_the_key_of_a_server_is_nowhere_in_the_state_directory(
    stored_plan: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The key of a server is never written in the state directory."""
    assert _approve_build(monkeypatch) == 0

    for device in ("build1", "build2"):
        key = _key(device)
        for path in sorted(approve.state_dir().rglob("*")):
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            assert key not in text, path


def test_a_wrong_confirmation_writes_no_token(
    stored_plan: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The owner has to type the confirmation."""
    assert _approve_build(monkeypatch, confirmation="yes") == 1

    assert not _approval_path().exists()


def test_an_empty_passphrase_writes_no_token(
    stored_plan: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The passphrase may not be empty."""
    assert _approve_build(monkeypatch, passphrase="") == 1

    assert not _approval_path().exists()


def test_a_plan_that_is_not_a_build_plan_is_refused(
    state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A plan file that is not a plan of ``plan_build`` is refused."""
    path = state_dir / "ad-build-plans" / f"{PLAN_ID}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"domain": {"dns_name": "ad-build.test"}}), "utf-8")

    assert _approve_build(monkeypatch) == 1

    assert not _approval_path().exists()
    assert "plan" in capsys.readouterr().err


def test_a_missing_plan_is_refused(
    state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A plan that is not there is a refusal, not a crash."""
    assert _approve_build(monkeypatch) == 1

    assert not _approval_path().exists()


def test_a_plan_approval_asks_the_passphrase_twice_without_a_fingerprint(
    stored_plan: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A passphrase no fingerprint on record confirms is asked twice.

    The setup of a server writes the fingerprint of its key; without
    it, a typo of the passphrase would be taken for the passphrase, and
    the DSRM and the admin password would come from the wrong key.
    """
    answers = iter(("typo", PASSPHRASE))
    monkeypatch.setattr(
        approve, "_getpass", lambda prompt: next(answers), raising=True
    )
    monkeypatch.setattr(
        "sys.stdin", io.StringIO(f"approve {PLAN_ID[:8]}\n"), raising=True
    )

    assert approve.approve_ad_build(PLAN_ID, now=NOW) == 1

    assert not _approval_path().exists()
    assert "DSRM password" not in capsys.readouterr().out


def test_the_plan_approval_refuses_a_passphrase_against_a_stored_fingerprint(
    stored_plan: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A passphrase the fingerprint of the setup does not match refuses."""
    _write_setup_fingerprint("build1", "other")

    assert _approve_build(monkeypatch) == 1

    assert not _approval_path().exists()
    assert "DSRM password" not in capsys.readouterr().out


# --------------------------------------------------------------------------
# The stage approval
# --------------------------------------------------------------------------


def test_the_stage_token_verifies_against_the_stage_digest(
    stored_plan: Path,
    state_dir: Path,
    built_plan: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The stage token is over the stage digest of the checkpoint."""
    _write_run_state(state_dir, built_plan)
    assert _approve_build(monkeypatch) == 0

    assert _approve_stage(monkeypatch, "2") == 0

    record = json.loads(_stage_approval_path("2").read_text(encoding="utf-8"))
    entry = record["servers"]["build1"]
    digest = plan.digest(built_plan)
    expected = plan.stage_digest(digest, "2", CHECKPOINT_ID)
    assert entry["stage_digest"] == expected
    assert entry["token"] == approve.approval_token(
        _key("build1"), expected, record["nbf"], record["exp"]
    )


def test_the_stage_token_window_is_thirty_minutes(
    stored_plan: Path,
    state_dir: Path,
    built_plan: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A stage token is good for thirty minutes (PLAN-1.5, Constraints)."""
    _write_run_state(state_dir, built_plan)
    assert _approve_build(monkeypatch) == 0

    assert _approve_stage(monkeypatch, "2") == 0

    record = json.loads(_stage_approval_path("2").read_text(encoding="utf-8"))
    assert record["nbf"] == int(NOW.timestamp())
    assert record["exp"] - record["nbf"] == STAGE_WINDOW_S


def test_the_stage_approval_calls_the_adapter_itself(
    stored_plan: Path,
    state_dir: Path,
    built_plan: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The checkpoint is verified through the adapter, not through the
    runner's state file.  The adapter is told the bound the helper's
    journal gives: stage 1 completed after the plan approval's NBF, so
    ``not_before`` is that completion, not the NBF (DESIGN-1.5
    "Checkpoints"), and the journal was read through the transport with
    a status of stage 0 under the plan token."""
    _write_run_state(state_dir, built_plan)
    assert _approve_build(monkeypatch) == 0
    record = json.loads(_approval_path().read_text(encoding="utf-8"))
    stage_one_done = record["nbf"] + 120
    verifier = FakeVerifier()
    transport = JournalTransport({stage: stage_one_done for stage in ("0", "1")})

    assert _approve_stage(monkeypatch, "2", verifier=verifier, transport=transport) == 0

    assert len(verifier.calls) == 1
    server_cfg, checkpoint, kind = verifier.calls[0]
    assert server_cfg["device"] == "build1"
    assert server_cfg["role"] == "dc1"
    assert checkpoint == {"name": CHECKPOINT_NAME, "id": CHECKPOINT_ID}
    assert kind == "workgroup"
    assert verifier.stages == ["2"]
    assert verifier.bounds == [stage_one_done]
    assert [device for device, _ in transport.requests] == ["build1"]
    _, request = transport.requests[0]
    assert (request["stage"], request["action"]) == ("0", "status")
    assert request["token"] == record["tokens"]["build1"]
    assert (request["nbf"], request["exp"]) == (record["nbf"], record["exp"])


def test_the_stage_approval_refuses_an_adapter_that_takes_no_stage(
    stored_plan: Path,
    state_dir: Path,
    built_plan: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An adapter of the old shape, verify(server_cfg, cp, kind), cannot
    take the stage, so it cannot answer, and the stage is refused."""
    _write_run_state(state_dir, built_plan)
    assert _approve_build(monkeypatch) == 0
    capsys.readouterr()

    class _OldVerifier:
        def verify(self, server_cfg: Any, cp: Any, kind: str) -> bool:
            return True

    assert _approve_stage(monkeypatch, "2", verifier=_OldVerifier()) == 1
    assert _approve_stage(monkeypatch, "2", verifier=lambda s, c, k: True) == 1

    assert not _stage_approval_path("2").exists()
    assert "checkpoint_unverified" in capsys.readouterr().err


def test_the_stage_approval_refuses_an_unverified_checkpoint(
    stored_plan: Path,
    state_dir: Path,
    built_plan: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A checkpoint that does not verify stops the approval.

    The runner's state says the run stopped for approval, and the
    approval does not believe it: it asks the adapter itself, and the
    adapter says no.
    """
    _write_run_state(state_dir, built_plan)
    assert _approve_build(monkeypatch) == 0
    verifier = FakeVerifier(ok=False)

    assert _approve_stage(monkeypatch, "2", verifier=verifier) == 1

    assert not _stage_approval_path("2").exists()
    err = capsys.readouterr().err
    assert "checkpoint_unverified" in err


def test_the_stage_approval_refuses_an_adapter_that_cannot_answer(
    stored_plan: Path,
    state_dir: Path,
    built_plan: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An adapter that cannot answer refuses the approval."""
    _write_run_state(state_dir, built_plan)
    assert _approve_build(monkeypatch) == 0

    assert _approve_stage(monkeypatch, "2", verifier=RaisingVerifier()) == 1

    assert not _stage_approval_path("2").exists()


def test_the_stage_approval_says_why_the_adapter_could_not_answer(
    stored_plan: Path,
    state_dir: Path,
    built_plan: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An adapter with no verify says so, and not only that it failed."""
    _write_run_state(state_dir, built_plan)
    assert _approve_build(monkeypatch) == 0

    assert _approve_stage(monkeypatch, "2", verifier=object()) == 1

    assert not _stage_approval_path("2").exists()
    assert "TypeError" in capsys.readouterr().err


def test_the_stage_approval_refuses_without_an_adapter(
    stored_plan: Path,
    state_dir: Path,
    built_plan: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without an adapter the checkpoint cannot be verified."""
    _write_run_state(state_dir, built_plan)
    assert _approve_build(monkeypatch) == 0

    assert (
        approve.approve_ad_build_stage(PLAN_ID, "2", verifier=None, now=NOW) == 1
    )

    assert not _stage_approval_path("2").exists()


def test_the_stage_approval_prints_the_checkpoint_and_the_restore_cost(
    stored_plan: Path,
    state_dir: Path,
    built_plan: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The owner sees the checkpoint and what it costs to restore it."""
    _write_run_state(state_dir, built_plan)
    assert _approve_build(monkeypatch) == 0

    assert _approve_stage(monkeypatch, "2") == 0

    out = capsys.readouterr().out
    assert CHECKPOINT_NAME in out
    assert CHECKPOINT_ID in out
    assert "Restore cost" in out


def test_the_stage_approval_says_what_a_wbadmin_checkpoint_costs(
    stored_plan: Path,
    state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A server without a hypervisor is restored from its own backup.

    The design takes an all-critical backup before stages 2 and 7 and a
    system-state backup before stages 3, 4 and 6; a system-state backup
    cannot undo a promotion, so it is never the one of stages 2 and 7.

    The stage-7 words are checked on the restore cost itself and through
    the approval in
    test_the_stage_approval_passes_stage_seven_to_a_wbadmin_adapter.
    """
    for stage in ("2", "7"):
        words = approve._restore_cost("wbadmin", stage)
        assert "bare-metal" in words
        assert "DSRM" in words
        assert "system-state" not in words
    assert approve.BUILD_WBADMIN_ALL_CRITICAL_STAGES == ("2", "7")

    inputs = copy.deepcopy(INPUTS)
    inputs["servers"][0]["checkpoint"] = "wbadmin"
    built = plan.plan_build(inputs)
    stored_plan.write_text(json.dumps(built), encoding="utf-8")
    assert _approve_build(monkeypatch) == 0
    capsys.readouterr()

    _write_run_state(
        state_dir,
        built,
        stage="3",
        servers={
            "build1": {
                "stage": "3",
                "state": "stopped_for_approval",
                "checkpoint": {"name": CHECKPOINT_NAME, "id": CHECKPOINT_ID},
                "checkpoint_kind": "dc",
            },
        },
    )

    assert _approve_stage(monkeypatch, "3") == 0

    out = capsys.readouterr().out
    assert "DSRM" in out
    assert "system-state" in out


def test_the_stage_approval_refuses_a_run_of_another_plan(
    stored_plan: Path,
    state_dir: Path,
    built_plan: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The run state of another plan is not this plan's approval."""
    _write_run_state(state_dir, built_plan, plan_digest="a" * 64)
    assert _approve_build(monkeypatch) == 0

    assert _approve_stage(monkeypatch, "2") == 1

    assert not _stage_approval_path("2").exists()
    assert "plan_mismatch" in capsys.readouterr().err


def test_the_stage_approval_refuses_without_a_plan_approval(
    stored_plan: Path,
    state_dir: Path,
    built_plan: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A stage of a plan the owner never approved gets no token.

    The runner's state file says the run stopped for approval, and the
    agent can write that file: only the approval of the plan says that
    the owner approved this plan.
    """
    _write_run_state(state_dir, built_plan)
    verifier = FakeVerifier()

    assert _approve_stage(monkeypatch, "2", verifier=verifier) == 1

    assert not _stage_approval_path("2").exists()
    assert "plan_mismatch" in capsys.readouterr().err
    assert verifier.calls == []


def test_the_stage_approval_refuses_a_plan_changed_after_its_approval(
    stored_plan: Path,
    state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A plan that changed after it was approved gets no token.

    The run state carries the digest of the plan that is running, and
    the agent can write that file too: the approval of the plan is what
    binds the stage to the bytes the owner read.
    """
    assert _approve_build(monkeypatch) == 0

    inputs = copy.deepcopy(INPUTS)
    inputs["domain"]["dns_name"] = "evil.test"
    changed = plan.plan_build(inputs)
    stored_plan.write_text(json.dumps(changed), encoding="utf-8")
    _write_run_state(state_dir, changed)
    verifier = FakeVerifier()

    assert _approve_stage(monkeypatch, "2", verifier=verifier) == 1

    assert not _stage_approval_path("2").exists()
    assert "plan_mismatch" in capsys.readouterr().err
    assert verifier.calls == []


def test_the_stage_approval_refuses_a_passphrase_other_than_the_plan_approval(
    stored_plan: Path,
    state_dir: Path,
    built_plan: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A stage is approved with the passphrase of the plan approval.

    The fingerprint of the plan approval is the fingerprint of the key
    of the server; a passphrase that is not the one of the plan
    approval mints a token no helper would accept.
    """
    _write_run_state(state_dir, built_plan)
    assert _approve_build(monkeypatch) == 0

    assert _approve_stage(monkeypatch, "2", passphrase="other") == 1

    assert not _stage_approval_path("2").exists()


def test_the_stage_approval_refuses_a_stage_that_is_done(
    stored_plan: Path,
    state_dir: Path,
    built_plan: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A stage the runner says is done gets no token."""
    _write_run_state(
        state_dir,
        built_plan,
        servers={
            "build1": {
                "stage": "2",
                "state": "done",
                "checkpoint": {"name": CHECKPOINT_NAME, "id": CHECKPOINT_ID},
                "checkpoint_kind": "workgroup",
            },
        },
    )
    assert _approve_build(monkeypatch) == 0

    assert _approve_stage(monkeypatch, "2") == 1

    assert not _stage_approval_path("2").exists()
    assert "already_done" in capsys.readouterr().err


def test_the_stage_approval_refuses_a_checkpoint_of_the_wrong_kind(
    stored_plan: Path,
    state_dir: Path,
    built_plan: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Stage 2 takes a workgroup checkpoint, not a DC one."""
    _write_run_state(
        state_dir,
        built_plan,
        servers={
            "build1": {
                "stage": "2",
                "state": "stopped_for_approval",
                "checkpoint": {"name": CHECKPOINT_NAME, "id": CHECKPOINT_ID},
                "checkpoint_kind": "dc",
            },
        },
    )
    assert _approve_build(monkeypatch) == 0
    verifier = FakeVerifier()

    assert _approve_stage(monkeypatch, "2", verifier=verifier) == 1

    assert not _stage_approval_path("2").exists()
    assert "schema" in capsys.readouterr().err
    assert verifier.calls == []


def test_the_stage_approval_refuses_a_checkpoint_without_an_id(
    stored_plan: Path,
    state_dir: Path,
    built_plan: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A checkpoint without an id is not a checkpoint of the stage.

    The id of the checkpoint is in the signed bytes of the token, so a
    checkpoint without one may not be signed at all.
    """
    _write_run_state(
        state_dir,
        built_plan,
        servers={
            "build1": {
                "stage": "2",
                "state": "stopped_for_approval",
                "checkpoint": {"name": CHECKPOINT_NAME},
                "checkpoint_kind": "workgroup",
            },
        },
    )
    assert _approve_build(monkeypatch) == 0
    verifier = FakeVerifier()

    assert _approve_stage(monkeypatch, "2", verifier=verifier) == 1

    assert not _stage_approval_path("2").exists()
    assert "schema" in capsys.readouterr().err
    assert verifier.calls == []


def test_the_stage_approval_refuses_a_checkpoint_id_that_is_not_text(
    stored_plan: Path,
    state_dir: Path,
    built_plan: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An id that is not text may not be signed as text."""
    _write_run_state(
        state_dir,
        built_plan,
        servers={
            "build1": {
                "stage": "2",
                "state": "stopped_for_approval",
                "checkpoint": {"name": CHECKPOINT_NAME, "id": 12345},
                "checkpoint_kind": "workgroup",
            },
        },
    )
    assert _approve_build(monkeypatch) == 0
    verifier = FakeVerifier()

    assert _approve_stage(monkeypatch, "2", verifier=verifier) == 1

    assert not _stage_approval_path("2").exists()
    assert "schema" in capsys.readouterr().err
    assert verifier.calls == []


def test_the_stage_approval_refuses_a_stage_the_plan_does_not_have(
    stored_plan: Path,
    state_dir: Path,
    built_plan: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Stage 7 does not exist in a plan of one server."""
    one_server = copy.deepcopy(INPUTS)
    del one_server["servers"][1]
    built = plan.plan_build(one_server)
    stored_plan.write_text(json.dumps(built), encoding="utf-8")
    assert _approve_build(monkeypatch) == 0
    _write_run_state(
        state_dir,
        built,
        stage="7",
        servers={
            "build1": {
                "stage": "7",
                "state": "stopped_for_approval",
                "checkpoint": {"name": CHECKPOINT_NAME, "id": CHECKPOINT_ID},
                "checkpoint_kind": "dc",
            },
        },
    )
    verifier = FakeVerifier()

    assert _approve_stage(monkeypatch, "7", verifier=verifier) == 1

    assert not _stage_approval_path("7").exists()
    assert "schema" in capsys.readouterr().err
    assert verifier.calls == []


def test_the_stage_approval_refuses_a_read_stage(
    stored_plan: Path,
    state_dir: Path,
    built_plan: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A read stage is covered by the plan token."""
    _write_run_state(
        state_dir,
        built_plan,
        stage="0",
        servers={
            "build1": {
                "stage": "0",
                "state": "stopped_for_approval",
                "checkpoint": {"name": CHECKPOINT_NAME, "id": CHECKPOINT_ID},
                "checkpoint_kind": "workgroup",
            },
        },
    )
    assert _approve_build(monkeypatch) == 0

    assert _approve_stage(monkeypatch, "0") == 1

    assert not _stage_approval_path("0").exists()
    assert "schema" in capsys.readouterr().err


def test_the_stage_approval_refuses_stage_nine(
    stored_plan: Path,
    state_dir: Path,
    built_plan: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Stage 9 is covered by the plan token, never by a stage token.

    The maintainer, 2026-11-13: the final stage runs under the plan approval, so
    the stage approval writes no token for it.
    """
    _write_run_state(
        state_dir,
        built_plan,
        stage="9",
        servers={
            "build1": {
                "stage": "9",
                "state": "stopped_for_approval",
                "checkpoint": {"name": CHECKPOINT_NAME, "id": CHECKPOINT_ID},
                "checkpoint_kind": "workgroup",
            },
        },
    )
    assert _approve_build(monkeypatch) == 0

    assert _approve_stage(monkeypatch, "9") == 1

    assert not _stage_approval_path("9").exists()
    err = capsys.readouterr().err
    assert "schema" in err
    assert "stage 9" in err
    assert "plan token" in err
    assert "awaits" not in err


def test_the_stage_approval_refuses_an_expired_plan_approval(
    stored_plan: Path,
    state_dir: Path,
    built_plan: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A stage approval needs a plan approval that is still open
    (the maintainer, 2026-11-13): at or past its EXP it is refused, and the adapter
    and the passphrase are not asked.  Here the run waits at stage 2 with
    its checkpoint taken, so the refusal names a resume plan at stage 2,
    never a second approval of this plan: that approval's NBF moves the
    checkpoint's bound past the waiting checkpoint, the adapters refuse
    it, and the runner never takes it again (F1 of tri-e1; open point
    52)."""
    _write_run_state(state_dir, built_plan)
    assert _approve_build(monkeypatch) == 0
    record = json.loads(_approval_path().read_text(encoding="utf-8"))
    capsys.readouterr()

    for past in (record["exp"], record["exp"] + 1):
        verifier = FakeVerifier()
        monkeypatch.setattr(approve, "_getpass", _never_getpass, raising=True)
        monkeypatch.setattr(
            "sys.stdin",
            io.StringIO(f"approve stage 2 of {PLAN_ID[:8]}\n"),
            raising=True,
        )
        later = datetime.fromtimestamp(past, tz=timezone.utc)
        assert (
            approve.approve_ad_build_stage(
                PLAN_ID, "2", verifier=verifier, transport=JournalTransport(), now=later
            )
            == 1
        )
        assert verifier.calls == []
        assert not _stage_approval_path("2").exists()
        err = capsys.readouterr().err
        assert "expired" in err
        assert "resume plan" in err
        assert "start_stage 2" in err
        assert "re-approve the plan" not in err
        assert approve.build_plan_approve_command(PLAN_ID) not in err

    # one second before the EXP the plan approval still holds
    before = datetime.fromtimestamp(record["exp"] - 1, tz=timezone.utc)
    assert _approve_stage(monkeypatch, "2", now=before) == 0


@pytest.mark.parametrize(
    "servers",
    [
        None,
        {"build1": {"stage": "1", "state": "running"}},
        {
            "build1": {
                "stage": "3",
                "state": "stopped_for_approval",
                "checkpoint": {"name": CHECKPOINT_NAME, "id": CHECKPOINT_ID},
                "checkpoint_kind": "workgroup",
            },
        },
        {"build1": {"stage": "2", "state": "stopped_for_approval", "checkpoint_kind": "workgroup"}},
        {
            "build1": {
                "stage": "2",
                "state": "stopped",
                "checkpoint": {"name": CHECKPOINT_NAME, "id": CHECKPOINT_ID},
                "checkpoint_kind": "workgroup",
            },
        },
    ],
    ids=["no-run-state", "running-before", "waiting-other-stage", "waiting-no-checkpoint", "stopped-not-waiting"],
)
def test_an_expired_plan_approval_without_a_waiting_checkpoint_says_re_approve(
    stored_plan: Path,
    state_dir: Path,
    built_plan: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    servers: dict[str, Any] | None,
) -> None:
    """With no server waiting at this stage with a checkpoint taken, no
    checkpoint is stranded by a new NBF, so the expired refusal still
    names the plan approval command and no resume plan."""
    if servers is not None:
        _write_run_state(state_dir, built_plan, servers=servers)
    assert _approve_build(monkeypatch) == 0
    record = json.loads(_approval_path().read_text(encoding="utf-8"))
    capsys.readouterr()
    monkeypatch.setattr(approve, "_getpass", _never_getpass, raising=True)
    later = datetime.fromtimestamp(record["exp"], tz=timezone.utc)
    verifier = FakeVerifier()

    assert approve.approve_ad_build_stage(
        PLAN_ID, "2", verifier=verifier, transport=JournalTransport(), now=later
    ) == 1

    assert verifier.calls == []
    assert not _stage_approval_path("2").exists()
    err = capsys.readouterr().err
    assert "expired" in err
    assert "re-approve the plan" in err
    assert approve.build_plan_approve_command(PLAN_ID) in err
    assert "resume plan" not in err


def test_an_expired_plan_approval_of_another_runs_state_says_re_approve(
    stored_plan: Path,
    state_dir: Path,
    built_plan: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A run state of another plan digest says nothing of this plan's
    checkpoints: the expired refusal does not read a resume plan into it."""
    _write_run_state(state_dir, built_plan, plan_digest="0" * 64)
    assert _approve_build(monkeypatch) == 0
    record = json.loads(_approval_path().read_text(encoding="utf-8"))
    capsys.readouterr()
    monkeypatch.setattr(approve, "_getpass", _never_getpass, raising=True)
    later = datetime.fromtimestamp(record["exp"], tz=timezone.utc)

    assert approve.approve_ad_build_stage(
        PLAN_ID, "2", verifier=FakeVerifier(), transport=JournalTransport(), now=later
    ) == 1

    err = capsys.readouterr().err
    assert "re-approve the plan" in err
    assert "resume plan" not in err


def test_the_stage_approval_refuses_a_plan_approval_without_an_expiry(
    stored_plan: Path,
    state_dir: Path,
    built_plan: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A plan approval whose EXP is not a number is never open.  The run
    waits at stage 2 with its checkpoint taken, so the refusal names a
    resume plan, as for an EXP that has passed (F1 of tri-e1)."""
    _write_run_state(state_dir, built_plan)
    assert _approve_build(monkeypatch) == 0
    path = _approval_path()
    for bad in (None, "9999999999", True):
        record = json.loads(path.read_text(encoding="utf-8"))
        record["exp"] = bad
        path.write_text(json.dumps(record), encoding="utf-8")
        capsys.readouterr()
        assert _approve_stage(monkeypatch, "2") == 1
        assert not _stage_approval_path("2").exists()
        err = capsys.readouterr().err
        assert "holds no expiry" in err
        assert "start_stage 2" in err
        assert "re-approve the plan" not in err


def test_the_stage_approval_refuses_a_stage_outside_the_design(
    stored_plan: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A stage that is not one of the design has no token."""
    assert _approve_build(monkeypatch) == 0
    verifier = FakeVerifier()

    assert _approve_stage(monkeypatch, "11", verifier=verifier) == 1

    assert not _stage_approval_path("11").exists()
    assert "schema" in capsys.readouterr().err
    assert verifier.calls == []


def test_the_stage_approval_writes_nothing_without_a_run_state(
    stored_plan: Path,
    built_plan: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A run that has not stopped for approval has no stage token."""
    assert _approve_build(monkeypatch) == 0

    assert _approve_stage(monkeypatch, "2") == 1

    assert not _stage_approval_path("2").exists()


def test_the_stage_approval_writes_nothing_when_the_confirmation_is_wrong(
    stored_plan: Path,
    state_dir: Path,
    built_plan: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The owner has to type the confirmation."""
    _write_run_state(state_dir, built_plan)
    assert _approve_build(monkeypatch) == 0

    assert _approve_stage(monkeypatch, "2", confirmation="yes") == 1

    assert not _stage_approval_path("2").exists()


def test_the_stage_approval_writes_a_token_for_every_server_that_waits(
    stored_plan: Path,
    state_dir: Path,
    built_plan: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every server that waits for the approval gets its own token."""
    _write_run_state(
        state_dir,
        built_plan,
        stage="7",
        servers={
            "build1": {
                "stage": "7",
                "state": "stopped_for_approval",
                "checkpoint": {"name": "m-hvcp-2", "id": CHECKPOINT_ID},
                "checkpoint_kind": "dc",
            },
            "build2": {
                "stage": "7",
                "state": "stopped_for_approval",
                "checkpoint": {"name": "pve-snap-1", "id": "a" * 36},
                "checkpoint_kind": "workgroup",
            },
        },
    )
    assert _approve_build(monkeypatch) == 0

    assert _approve_stage(monkeypatch, "7") == 0

    record = json.loads(_stage_approval_path("7").read_text(encoding="utf-8"))
    assert set(record["servers"]) == {"build1", "build2"}
    digest = plan.digest(built_plan)
    assert record["servers"]["build1"]["stage_digest"] == plan.stage_digest(
        digest, "7", CHECKPOINT_ID
    )
    assert record["servers"]["build2"]["stage_digest"] == plan.stage_digest(
        digest, "7", "a" * 36
    )
    assert record["servers"]["build1"]["token"] != record["servers"]["build2"][
        "token"
    ]


def test_the_stage_approval_refuses_an_approval_copied_from_another_plan(
    stored_plan: Path,
    state_dir: Path,
    built_plan: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An approval record proves nothing for a plan it was not minted for.

    The plan approval file is in a directory the agent can write.  Its
    fingerprints depend on the passphrase and the device, not on the
    plan, so a record copied from an approved plan onto another plan,
    with the plan id and the digest swapped, must not let the owner mint
    a stage token for a plan they never saw: the plan tokens of the
    record are over the digest of the plan that was approved.
    """
    assert _approve_build(monkeypatch) == 0
    genuine = json.loads(_approval_path().read_text(encoding="utf-8"))

    other_id = "f" * 32
    inputs = copy.deepcopy(INPUTS)
    inputs["domain"]["dns_name"] = "evil.test"
    other = plan.plan_build(inputs)
    other_digest = plan.digest(other)
    plans = state_dir / "ad-build-plans"
    (plans / f"{other_id}.json").write_text(json.dumps(other), encoding="utf-8")
    forged = dict(genuine, plan_id=other_id, plan_digest=other_digest)
    _approval_path(other_id).write_text(json.dumps(forged), encoding="utf-8")
    (plans / f"{other_id}.run.json").write_text(
        json.dumps(
            {
                "plan_id": other_id,
                "plan_digest": other_digest,
                "state": "stopped_for_approval",
                "stage": "2",
                "servers": {
                    "build1": {
                        "stage": "2",
                        "state": "stopped_for_approval",
                        "checkpoint": {"name": CHECKPOINT_NAME, "id": CHECKPOINT_ID},
                        "checkpoint_kind": "workgroup",
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    capsys.readouterr()

    assert _approve_stage(monkeypatch, "2", plan_id=other_id) == 1

    assert not _stage_approval_path("2", other_id).exists()
    assert "plan_mismatch" in capsys.readouterr().err


class _AnswerVerifier:
    """An object adapter whose ``verify`` gives one fixed answer."""

    def __init__(self, answer: Any) -> None:
        self.answer = answer

    def verify(self, server_cfg: Any, cp: Any, kind: str, *, stage: str, not_before: int) -> Any:
        return self.answer


def _answer_lambda(answer: Any) -> Any:
    return lambda s, c, k, *, stage, not_before: answer


@pytest.mark.parametrize(
    "make_adapter",
    [_answer_lambda, _AnswerVerifier],
    ids=["callable", "object-verify"],
)
@pytest.mark.parametrize("answer", ["unverified", {"ok": False}, 1])
def test_the_stage_approval_refuses_an_adapter_answer_that_is_not_true(
    answer: Any,
    make_adapter: Any,
    stored_plan: Path,
    state_dir: Path,
    built_plan: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Only True verifies a checkpoint; a truthy answer of another type
    is not a yes, from an object adapter's ``verify`` as from a callable."""
    _write_run_state(state_dir, built_plan)
    assert _approve_build(monkeypatch) == 0
    capsys.readouterr()

    assert (
        _approve_stage(monkeypatch, "2", verifier=make_adapter(answer)) == 1
    )

    assert not _stage_approval_path("2").exists()
    assert "checkpoint_unverified" in capsys.readouterr().err


def _wbadmin_stage(
    stored_plan: Path,
    state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
) -> None:
    """A plan whose DC1 has no hypervisor, stopped before one stage."""
    inputs = copy.deepcopy(INPUTS)
    inputs["servers"][0]["checkpoint"] = "wbadmin"
    built = plan.plan_build(inputs)
    stored_plan.write_text(json.dumps(built), encoding="utf-8")
    assert _approve_build(monkeypatch) == 0
    _write_run_state(
        state_dir,
        built,
        stage=stage,
        servers={
            "build1": {
                "stage": stage,
                "state": "stopped_for_approval",
                "checkpoint": {"name": CHECKPOINT_NAME, "id": CHECKPOINT_ID},
                "checkpoint_kind": approve.BUILD_CHECKPOINT_OF_STAGE[("dc1", stage)],
            },
        },
    )


def test_the_stage_approval_passes_stage_seven_to_a_wbadmin_adapter(
    stored_plan: Path,
    state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Stage 7 of a server without a hypervisor reaches the adapter with
    its stage (the maintainer, 2026-11-13), so the adapter can demand the
    all-critical backup; the approval prints the bare-metal cost."""
    _wbadmin_stage(stored_plan, state_dir, monkeypatch, "7")
    capsys.readouterr()
    verifier = FakeVerifier(ok=True)

    assert _approve_stage(monkeypatch, "7", verifier=verifier) == 0

    assert verifier.stages == ["7"]
    assert verifier.calls[0][0]["checkpoint"] == "wbadmin"
    assert verifier.calls[0][2] == "dc"
    assert _stage_approval_path("7").exists()
    out = capsys.readouterr().out
    assert "bare-metal" in out


#: The "Can recover" items of a system-state backup (MEASURED-1.5,
#: ``wbadmin get versions`` after ``systemstatebackup``: "Can recover:
#: ... System State").
SYSTEM_STATE_ITEMS = ["System State"]

#: The "Can recover" items of an all-critical backup.  The design reads
#: "Bare Metal Recovery" in "Can recover"; the full line is captured in
#: task 7.
ALL_CRITICAL_ITEMS = ["Bare Metal Recovery", "System State"]


@pytest.mark.parametrize("stage", ["2", "7"])
def test_the_stage_approval_refuses_a_system_state_backup_for_a_promotion(
    stage: str,
    stored_plan: Path,
    state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A system-state backup cannot undo a promotion: the wbadmin adapter
    refuses it for the stages 2 and 7 and no token is written."""
    _wbadmin_stage(stored_plan, state_dir, monkeypatch, stage)
    capsys.readouterr()
    reads: list[str] = []

    def read(server_cfg: Any, cp: Any) -> list[str]:
        reads.append(cp["id"])
        return list(SYSTEM_STATE_ITEMS)

    verifier = WbadminVerifier(read)
    assert _approve_stage(monkeypatch, stage, verifier=verifier) == 1

    assert reads == [CHECKPOINT_ID]
    assert not _stage_approval_path(stage).exists()
    assert "checkpoint_unverified" in capsys.readouterr().err


@pytest.mark.parametrize("stage", ["2", "7"])
def test_the_stage_approval_accepts_an_all_critical_backup_for_a_promotion(
    stage: str,
    stored_plan: Path,
    state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _wbadmin_stage(stored_plan, state_dir, monkeypatch, stage)
    verifier = WbadminVerifier(
        lambda server_cfg, cp: list(ALL_CRITICAL_ITEMS)
    )
    assert _approve_stage(monkeypatch, stage, verifier=verifier) == 0
    assert _stage_approval_path(stage).exists()


def test_the_stage_approval_accepts_a_system_state_backup_for_stage_three(
    stored_plan: Path,
    state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _wbadmin_stage(stored_plan, state_dir, monkeypatch, "3")
    verifier = WbadminVerifier(
        lambda server_cfg, cp: list(SYSTEM_STATE_ITEMS)
    )
    assert _approve_stage(monkeypatch, "3", verifier=verifier) == 0
    assert _stage_approval_path("3").exists()


def _never_getpass(prompt: str) -> str:
    """A terminal that must not be asked for the passphrase."""
    raise AssertionError("the passphrase was asked for")


def test_the_stage_approval_refuses_a_locked_server_before_the_passphrase(
    stored_plan: Path,
    state_dir: Path,
    built_plan: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A server locked out by wrong answers refuses before getpass, as
    approve_ad_change does."""
    _write_run_state(state_dir, built_plan)
    assert _approve_build(monkeypatch) == 0
    capsys.readouterr()
    monkeypatch.setattr(approve, "_lock_remaining", lambda device: 600)
    monkeypatch.setattr(approve, "_getpass", _never_getpass)
    monkeypatch.setattr(
        "sys.stdin", io.StringIO(f"approve stage 2 of {PLAN_ID[:8]}\n")
    )

    assert (
        approve.approve_ad_build_stage(
            PLAN_ID, "2", verifier=FakeVerifier(), transport=JournalTransport(), now=NOW
        )
        == 1
    )

    assert not _stage_approval_path("2").exists()
    assert "too many wrong answers" in capsys.readouterr().err


def test_the_plan_approval_refuses_a_locked_server_before_the_passphrase(
    stored_plan: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The plan approval honours the lockout of every server too."""
    monkeypatch.setattr(approve, "_lock_remaining", lambda device: 600)
    monkeypatch.setattr(approve, "_getpass", _never_getpass)
    monkeypatch.setattr("sys.stdin", io.StringIO(f"approve {PLAN_ID[:8]}\n"))

    assert approve.approve_ad_build(PLAN_ID, now=NOW) == 1

    assert not _approval_path().exists()
    assert "too many wrong answers" in capsys.readouterr().err


def test_a_wrong_stage_passphrase_is_recorded_as_a_failure(
    stored_plan: Path,
    state_dir: Path,
    built_plan: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A passphrase that is not the plan approval's counts toward the
    lockout of the server."""
    _write_run_state(state_dir, built_plan)
    assert _approve_build(monkeypatch) == 0
    failures: list[str] = []
    monkeypatch.setattr(
        approve,
        "_record_failure",
        lambda device: failures.append(device) or 0,
    )

    assert _approve_stage(monkeypatch, "2", passphrase="other") == 1

    assert failures == ["build1"]
    assert not _stage_approval_path("2").exists()


def test_a_wrong_plan_passphrase_is_recorded_as_a_failure(
    stored_plan: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A passphrase the setup fingerprint refuses counts toward the
    lockout of the server."""
    _write_setup_fingerprint("build1", "other")
    failures: list[str] = []
    monkeypatch.setattr(
        approve,
        "_record_failure",
        lambda device: failures.append(device) or 0,
    )

    assert _approve_build(monkeypatch) == 1

    assert failures == ["build1"]
    assert not _approval_path().exists()


# --------------------------------------------------------------------------
# The stage approval with the real adapters of task 7
# --------------------------------------------------------------------------


def _hv_listing(checkpoint_type: str = "ProductionOnly", ident: str = CHECKPOINT_ID) -> str:
    """hv-checkpoint.ps1's answer to ``list``: a JSON array of one."""
    return json.dumps(
        [
            {
                "name": CHECKPOINT_NAME,
                "id": ident,
                "created": "2026-12-31T23:50:00Z",
                "vm": "BUILD1",
                "checkpoint_type": checkpoint_type,
            }
        ]
    )


def _real_adapters(listing: str, argvs: list[list[str]]) -> Any:
    ssh = ("ssh", "-o", "BatchMode=yes", "hv-checkpoint@hvhost.example.test")

    def run(argv: list[str]) -> tuple[int, str]:
        argvs.append(list(argv))
        return 0, listing

    hyperv = build_checkpoint.HyperVAdapter(
        {"build1": build_checkpoint.HyperVTarget(ssh=ssh, vm="BUILD1")},
        run=run,
        read_genid=lambda server_cfg: "",
        read_showbackup=lambda server_cfg: build_checkpoint.ShowbackupRead("", 0),
    )
    return build_checkpoint.CheckpointAdapters({"hyperv": hyperv})


#: 2026-12-31T23:00:00Z: the bound the tests give the real adapters,
#: before the listed checkpoint (23:50:00Z).
REAL_ADAPTER_BOUND = int(datetime(2026, 12, 31, 23, tzinfo=timezone.utc).timestamp())


class _Bounded:
    """A test double only: the real adapters with a fixed ``not_before``
    bound, so these tests reach the host read.  The product never wraps
    the adapters with a constant.  Task 8 passes not_before on every
    verify call from the helper's journal: the later of the plan
    approval's NBF and the previous stage's recorded completion."""

    def __init__(self, adapters: Any, not_before: int) -> None:
        self._adapters = adapters
        self._not_before = not_before

    def verify(self, server_cfg: Any, cp: Any, kind: str, *, stage: str, not_before: int) -> Any:
        # The bound the approval passed (the journal's) is replaced by
        # the fixed one: these tests are about the host read only.
        return self._adapters.verify(server_cfg, cp, kind, stage=stage, not_before=self._not_before)


def test_the_stage_approval_refuses_the_real_adapters_when_the_journal_cannot_be_read(
    stored_plan: Path,
    state_dir: Path,
    built_plan: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The real adapters are never called without the journal's bound (task
    8): when the helper's journal cannot be read, the approval refuses
    before the host is asked."""
    _write_run_state(state_dir, built_plan)
    assert _approve_build(monkeypatch) == 0
    capsys.readouterr()
    argvs: list[list[str]] = []
    assert _approve_stage(
        monkeypatch, "2", verifier=_real_adapters(_hv_listing(), argvs), transport=JournalTransport(fail=True)
    ) == 1
    assert argvs == []
    assert not _stage_approval_path("2").exists()
    assert "checkpoint_unverified" in capsys.readouterr().err


def test_the_stage_approval_verifies_through_the_hyperv_adapter(
    stored_plan: Path,
    state_dir: Path,
    built_plan: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The adapters of task 7 are the verifier the approval takes: the
    approval lists the checkpoint on the Hyper-V host itself."""
    _write_run_state(state_dir, built_plan)
    assert _approve_build(monkeypatch) == 0
    argvs: list[list[str]] = []

    assert _approve_stage(monkeypatch, "2", verifier=_Bounded(_real_adapters(_hv_listing(), argvs), REAL_ADAPTER_BOUND)) == 0

    assert argvs == [["ssh", "-o", "BatchMode=yes", "hv-checkpoint@hvhost.example.test", "list", "BUILD1"]]
    assert _stage_approval_path("2").exists()


def test_the_stage_approval_refuses_what_the_hyperv_adapter_refuses(
    stored_plan: Path,
    state_dir: Path,
    built_plan: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A checkpoint the host lists as Standard, or does not list, gets no
    stage token."""
    _write_run_state(state_dir, built_plan)
    assert _approve_build(monkeypatch) == 0
    capsys.readouterr()
    for listing in (_hv_listing("Standard"), _hv_listing(ident="0d8e7f6a-5b4c-4d3e-8f2a-1b0c9d8e7f6a"), "[]"):
        argvs: list[list[str]] = []
        assert _approve_stage(monkeypatch, "2", verifier=_Bounded(_real_adapters(listing, argvs), REAL_ADAPTER_BOUND)) == 1
        assert len(argvs) == 1
        assert not _stage_approval_path("2").exists()
        assert "checkpoint_unverified" in capsys.readouterr().err
