"""The approval of one Active Directory change (newton-approve ad-change).

The approver builds the canonical bytes itself and never reads the digest
of the plan file: the token covers the digest it computed, so a plan file
whose digest was edited changes nothing.
"""

from __future__ import annotations

import io
import json
from datetime import datetime, timezone
from pathlib import Path

import harness
import pytest

from newton_mcp import approve
from newton_mcp.ad.write import plan as ad_plan, request, store


PASSPHRASE = "correct horse battery staple"


@pytest.fixture(autouse=True)
def state_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """The state directory of the test."""
    root = tmp_path / "state"
    monkeypatch.setenv("NEWTON_STATE_DIR", str(root))
    return root


def _fingerprint(domain: str, passphrase: str = PASSPHRASE) -> str:
    """The fingerprint of the key of the domain."""
    global _FINGERPRINT
    if _FINGERPRINT is None:
        k_hex = approve.derive_k(passphrase.encode("utf-8"), domain)
        _FINGERPRINT = approve.approval_fingerprint(k_hex)
    return _FINGERPRINT


_FINGERPRINT: str | None = None


def _write_fingerprint(domain: str, passphrase: str = PASSPHRASE) -> None:
    """Write the fingerprint of the key of the domain, as the setup does."""
    path = store.state_dir() / "approval-fp" / domain
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text(f"v1 {_fingerprint(domain, passphrase)}\n", encoding="ascii")


def _make_plan(lab: harness.Lab, verb: str = "uac-clear", names: list[str] | None = None,
          value: object = 4194304) -> dict[str, object]:
    """The plan of one change, written in the state directory."""
    result = ad_plan.plan_change(
        harness.DOMAIN,
        verb,
        ["seed-asrep"] if names is None else names,
        value,
        send=lab.send,
        devices=lab.devices,
    )
    return result


def _approve(
    plan_id: str,
    monkeypatch: pytest.MonkeyPatch,
    *,
    passphrase: str = PASSPHRASE,
    confirmation: str | None = None,
) -> tuple[bool, str]:
    """Run the approval with a fixed terminal."""
    if confirmation is None:
        confirmation = f"approve {plan_id[:8]}"
    monkeypatch.setattr(
        approve, "_getpass", lambda prompt: passphrase, raising=True
    )
    monkeypatch.setattr(
        "sys.stdin", io.StringIO(confirmation + "\n"), raising=True
    )
    return approve.approve_ad_change(
        plan_id, now=datetime(2027, 1, 1, tzinfo=timezone.utc)
    )


def test_the_approval_writes_the_window_and_the_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The approval file holds nbf, exp and the token."""
    lab = harness.Lab()
    lab.add_user(uac=4260352)
    planned = _make_plan(lab)
    _write_fingerprint(harness.DOMAIN)

    ok, refusal = _approve(str(planned["plan_id"]), monkeypatch)

    assert ok, refusal
    approval = store.read_json(
        store.approval_path(str(planned["plan_id"]))
    )
    assert approval["nbf"] < approval["exp"]
    assert approval["exp"] - approval["nbf"] <= 1800
    assert len(approval["token"]) == 64


def test_the_approval_ignores_the_digest_of_the_plan_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An edited digest in the plan file changes nothing."""
    lab = harness.Lab()
    lab.add_user(uac=4260352)
    planned = _make_plan(lab)
    plan_id = str(planned["plan_id"])
    path = store.plan_path(plan_id)
    record = store.read_json(path)
    record["digest"] = "0" * 64
    path.write_text(json.dumps(record), encoding="utf-8")
    _write_fingerprint(harness.DOMAIN)

    ok, refusal = _approve(plan_id, monkeypatch)

    assert ok, refusal
    approval = store.read_json(store.approval_path(plan_id))
    plan_record = store.read_json(path)
    expected = request.digest(plan_record)
    assert approval["digest"] == expected
    assert approval["token"] == request.token(
        approve.derive_k(PASSPHRASE.encode("utf-8"), harness.DOMAIN),
        expected,
        approval["nbf"],
        approval["exp"],
    )


def test_the_approval_shows_every_field(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The owner sees the verb, the names, the ids, the images, the risk and the window."""
    lab = harness.Lab()
    lab.add_user(uac=4260352)
    planned = _make_plan(lab)
    _write_fingerprint(harness.DOMAIN)

    ok, refusal = _approve(str(planned["plan_id"]), monkeypatch)

    assert ok, refusal
    out = capsys.readouterr().out
    assert "uac-clear" in out
    assert "seed-asrep" in out
    assert harness.SEED_GUID in out
    assert harness.SEED_SID in out
    assert "4260352" in out
    assert "66048" in out
    assert "MED" in out
    assert "600" in out


def test_editing_the_risk_of_the_plan_file_changes_the_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The risk is in the canonical bytes: an edited risk is another change."""
    lab = harness.Lab()
    lab.add_user(uac=4260352, privileged=True)
    planned = _make_plan(lab)
    plan_id = str(planned["plan_id"])
    path = store.plan_path(plan_id)
    record = store.read_json(path)
    assert record["risk"] == "HIGH"
    original = request.digest(record)

    record["risk"] = "MED"
    path.write_text(json.dumps(record), encoding="utf-8")
    edited = request.digest(store.read_json(path))

    assert edited != original


def test_the_approval_mints_the_token_over_the_risk_it_shows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The owner approves the level the plan holds, and the token says so."""
    lab = harness.Lab()
    lab.add_user(uac=4260352, privileged=True)
    planned = _make_plan(lab)
    plan_id = str(planned["plan_id"])
    path = store.plan_path(plan_id)
    record = store.read_json(path)
    record["risk"] = "MED"
    path.write_text(json.dumps(record), encoding="utf-8")
    _write_fingerprint(harness.DOMAIN)

    ok, refusal = _approve(plan_id, monkeypatch)

    assert ok, refusal
    approval = store.read_json(store.approval_path(plan_id))
    expected = request.digest(store.read_json(path))
    assert approval["digest"] == expected
    assert approval["token"] == request.token(
        approve.derive_k(PASSPHRASE.encode("utf-8"), harness.DOMAIN),
        expected,
        approval["nbf"],
        approval["exp"],
    )


def test_the_approval_shows_the_high_risk_warning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A HIGH change shows the warning of the router flow."""
    lab = harness.Lab()
    lab.add_user(uac=4260352, privileged=True)
    planned = _make_plan(lab)
    _write_fingerprint(harness.DOMAIN)

    ok, refusal = _approve(str(planned["plan_id"]), monkeypatch)

    assert ok, refusal
    out = capsys.readouterr().out
    assert "HIGH RISK" in out
    assert "WHY THIS IS HIGH RISK" in out
    assert "privileged" in out


def test_the_approval_shows_the_password_of_a_user_create_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The password of a new account is shown at the approval and never in the approval file."""
    lab = harness.Lab()
    lab.add_user(uac=512)
    lab.add_domain_head()
    planned = _make_plan(lab, "user-create", ["newuser"], harness.DOMAIN_GUID)
    _write_fingerprint(harness.DOMAIN)

    ok, refusal = _approve(str(planned["plan_id"]), monkeypatch)

    assert ok, refusal
    secret = store.read_json(store.plan_path(str(planned["plan_id"])))["secret"]
    out = capsys.readouterr().out
    assert secret in out
    approval = store.read_json(store.approval_path(str(planned["plan_id"])))
    assert secret not in json.dumps(approval)


def test_the_password_is_shown_only_at_the_first_approval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A second run of newton-approve on the same plan never prints it again."""
    lab = harness.Lab()
    lab.add_user(uac=512)
    lab.add_domain_head()
    planned = _make_plan(lab, "user-create", ["newuser"], harness.DOMAIN_GUID)
    plan_id = str(planned["plan_id"])
    _write_fingerprint(harness.DOMAIN)
    new_secret = store.read_json(store.plan_path(plan_id))["secret"]

    ok, refusal = _approve(plan_id, monkeypatch)
    assert ok, refusal
    assert new_secret in capsys.readouterr().out

    ok, refusal = _approve(plan_id, monkeypatch)
    assert ok, refusal
    out = capsys.readouterr().out
    assert new_secret not in out
    assert "not shown again" in out


def test_a_refused_approval_never_prints_the_password(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The password is printed once the approval exists, never before."""
    lab = harness.Lab()
    lab.add_user(uac=512)
    lab.add_domain_head()
    planned = _make_plan(lab, "user-create", ["newuser"], harness.DOMAIN_GUID)
    plan_id = str(planned["plan_id"])
    _write_fingerprint(harness.DOMAIN)
    new_secret = store.read_json(store.plan_path(plan_id))["secret"]

    ok, _ = _approve(plan_id, monkeypatch, passphrase="wrong passphrase")
    assert not ok
    ok, _ = _approve(plan_id, monkeypatch, confirmation="no")
    assert not ok
    assert new_secret not in capsys.readouterr().out

    ok, refusal = _approve(plan_id, monkeypatch)
    assert ok, refusal
    out = capsys.readouterr().out
    assert new_secret in out
    assert out.index("Approved plan") < out.index(new_secret)


def test_the_approval_never_redacts_the_password(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A redactor that rewrites the password shows another password."""
    lab = harness.Lab()
    lab.add_user(uac=512)
    lab.add_domain_head()
    planned = _make_plan(lab, "user-create", ["newuser"], harness.DOMAIN_GUID)
    plan_id = str(planned["plan_id"])
    path = store.plan_path(plan_id)
    record = store.read_json(path)
    secret = "password=hunter2hunter2"
    record["secret"] = secret
    path.write_text(json.dumps(record), encoding="utf-8")
    _write_fingerprint(harness.DOMAIN)

    ok, refusal = _approve(plan_id, monkeypatch)

    assert ok, refusal
    out = capsys.readouterr().out
    assert secret in out
    assert approve._masked(secret) not in out


def test_the_sanitising_leaves_a_generated_password_alone() -> None:
    """The alphabet of the passwords is printable ASCII: it survives the screen."""
    for _ in range(200):
        password = ad_plan._password()

        assert approve._sanitize_terminal_value(password) == password


def test_a_wrong_passphrase_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A wrong passphrase mints no approval."""
    lab = harness.Lab()
    lab.add_user(uac=4260352)
    planned = _make_plan(lab)
    _write_fingerprint(harness.DOMAIN)

    ok, refusal = _approve(
        str(planned["plan_id"]), monkeypatch, passphrase="wrong passphrase"
    )

    assert not ok
    assert "approval not created" in refusal
    assert not store.approval_path(str(planned["plan_id"])).exists()


def test_a_missing_fingerprint_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Without a fingerprint on record there is no key to check.

    The refusal names the setup command of the Active Directory path,
    never the one of the router path.
    """
    lab = harness.Lab()
    lab.add_user(uac=4260352)
    planned = _make_plan(lab)

    ok, refusal = _approve(str(planned["plan_id"]), monkeypatch)

    assert not ok
    assert (
        "no approval fingerprint on record for win-dc1; "
        "run sudo -u newton /usr/local/bin/newton-ad-setup approval-key "
        "win-dc1 on the Newton host first (from a source tree: "
        "scripts/newton-ad-setup approval-key win-dc1); approval not created"
    ) in refusal
    assert "newton-router-setup" not in refusal


def test_a_wrong_confirmation_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The owner has to type the confirmation."""
    lab = harness.Lab()
    lab.add_user(uac=4260352)
    planned = _make_plan(lab)
    _write_fingerprint(harness.DOMAIN)

    ok, refusal = _approve(
        str(planned["plan_id"]), monkeypatch, confirmation="yes"
    )

    assert not ok
    assert "confirmation did not match" in refusal


def test_the_command_is_the_ad_change_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """newton-approve ad-change <plan_id> is the way in."""
    lab = harness.Lab()
    lab.add_user(uac=4260352)
    planned = _make_plan(lab)
    _write_fingerprint(harness.DOMAIN)
    monkeypatch.setattr(approve, "_getpass", lambda prompt: PASSPHRASE, raising=True)
    monkeypatch.setattr("sys.stdin", io.StringIO(f"approve {str(planned['plan_id'])[:8]}\n"), raising=True)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True, raising=True)

    code = approve.main(["ad-change", str(planned["plan_id"])])

    assert code == 0
    assert store.approval_path(str(planned["plan_id"])).exists()


def test_the_command_refuses_a_plan_that_does_not_exist(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A plan that is not there is a refusal, not a crash."""
    monkeypatch.setattr("sys.stdin.isatty", lambda: True, raising=True)

    code = approve.main(["ad-change", "0" * 32])

    assert code == 1


def test_the_ad_tools_name_the_installed_approve_command() -> None:
    """The plan and apply tools tell the agent the command the owner
    runs on an installed Newton: the newton-approve launcher, through
    the owner's own sudo, as the newton user."""
    import asyncio

    from mcp.shared.memory import create_connected_server_and_client_session

    from newton_mcp import server

    async def listed():
        async with create_connected_server_and_client_session(
            server.mcp._mcp_server
        ) as session:
            await session.initialize()
            return await session.list_tools()

    tools = {tool.name: tool for tool in asyncio.run(listed()).tools}
    command = "sudo -u newton /usr/local/bin/newton-approve ad-change <plan_id>"
    for name in ("newton_ad_plan_change", "newton_ad_apply_change"):
        description = tools[name].description or ""
        assert command in " ".join(description.split()), name
