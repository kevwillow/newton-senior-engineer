"""the ``newton-rpcd`` setup CLI.

The CLI is what the setup uses to talk to the router's own web API
before Newton manages anything: it prints the group lists, computes the
certificate pin, checks that the login works and that the router grants
exactly the groups Newton asked for, and proves that a removed login is
refused.

The password is read from a file with the same rules the inventory uses
for a password file, and it never reaches the screen.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from newton_mcp import rpcd_cli
from rpcd_helpers import Router, ok, pin_of, self_signed

PASSWORD = "synthetic-rpcd-password-9f3c"

MEASURED_ACLS = {
    "luci-base": ["read", "write"],
    "luci-base-network-status": ["read"],
    "luci-mod-network-config": ["read", "write"],
    "luci-mod-network-dhcp": ["read"],
    "luci-mod-network-diagnostics": ["read"],
    "luci-mod-status-index": ["read"],
    "luci-mod-status-logs": ["read"],
}


def _password_file(tmp_path: Path, mode: int = 0o600, text: str = PASSWORD) -> Path:
    path = tmp_path / "rpcd-password"
    path.write_text(text + "\n", encoding="utf-8")
    path.chmod(mode)
    return path


def _login_answer(acls: dict | None = None) -> tuple[int, bytes]:
    return ok([
        0,
        {
            "ubus_rpc_session": "0123456789abcdef0123456789abcdef",
            "ubus_rpc_session_expiry": 30,
            "acls": {"access-group": acls if acls is not None else MEASURED_ACLS},
        },
    ])


def _run(argv, capsys) -> tuple[int, str]:
    code = rpcd_cli.main(argv)
    captured = capsys.readouterr()
    return code, captured.out + captured.err


# ---- groups ----------------------------------------------------------------


def test_groups_prints_the_read_write_and_never_lists(capsys) -> None:
    code, output = _run(["groups"], capsys)
    assert code == 0
    lines = output.splitlines()
    assert "read luci-base" in lines
    assert "write luci-mod-network-config" in lines
    assert "never luci-mod-system-ssh" in lines
    # the never list comes after the read and write lists
    assert max(i for i, line in enumerate(lines) if line.startswith("read ")) < min(
        i for i, line in enumerate(lines) if line.startswith("never ")
    )


def test_groups_lists_every_measured_group(capsys) -> None:
    from newton_mcp.adapters import openwrt_rpcd as rpcd

    code, output = _run(["groups"], capsys)
    assert code == 0
    for group in rpcd.READ_GROUPS:
        assert f"read {group}" in output
    for group in rpcd.WRITE_GROUPS:
        assert f"write {group}" in output
    for group in rpcd.NEVER_GROUPS:
        assert f"never {group}" in output


# ---- pin -------------------------------------------------------------------


def test_pin_prints_the_pin(tmp_path, capsys) -> None:
    cert_pem, _key_pem, cert_der = self_signed()
    cert = tmp_path / "uhttpd.crt"
    cert.write_bytes(cert_der)
    code, output = _run(["pin", str(cert)], capsys)
    assert code == 0
    assert output.strip() == pin_of(cert_pem)


def test_pin_accepts_a_pem_certificate(tmp_path, capsys) -> None:
    cert_pem, _key_pem, cert_der = self_signed()
    cert = tmp_path / "uhttpd.pem"
    cert.write_bytes(cert_pem)
    code, output = _run(["pin", str(cert)], capsys)
    assert code == 0
    assert output.strip() == pin_of(cert_pem)


def test_pin_of_garbage_fails(tmp_path, capsys) -> None:
    cert = tmp_path / "uhttpd.crt"
    cert.write_bytes(b"not a certificate")
    code, output = _run(["pin", str(cert)], capsys)
    assert code == 1
    assert output.strip()


def test_pin_of_a_missing_file_fails(tmp_path, capsys) -> None:
    code, output = _run(["pin", str(tmp_path / "nope.crt")], capsys)
    assert code == 1
    assert output.strip()


# ---- verify ----------------------------------------------------------------


def test_verify_passes_against_a_router_with_the_measured_groups(tmp_path, capsys) -> None:
    cert_pem, key_pem, cert_der = self_signed()
    password = _password_file(tmp_path)
    with Router(cert_pem, key_pem, lambda body: _login_answer()) as router:
        code, output = _run(
            [
                "verify",
                "--host", "127.0.0.1",
                "--port", str(router.port),
                "--pin", pin_of(cert_pem),
                "--password-file", str(password),
            ],
            capsys,
        )
    assert code == 0
    assert "PASS login and groups" in output
    assert PASSWORD not in output


def test_verify_fails_when_a_group_is_missing(tmp_path, capsys) -> None:
    cert_pem, key_pem, _cert_der = self_signed()
    password = _password_file(tmp_path)
    acls = dict(MEASURED_ACLS)
    acls.pop("luci-mod-status-logs")
    with Router(cert_pem, key_pem, lambda body: _login_answer(acls)) as router:
        code, output = _run(
            [
                "verify",
                "--host", "127.0.0.1",
                "--port", str(router.port),
                "--pin", pin_of(cert_pem),
                "--password-file", str(password),
            ],
            capsys,
        )
    assert code == 1
    assert "FAIL" in output
    assert "luci-mod-status-logs" in output
    assert "PASS" not in output


def test_verify_fails_when_the_login_is_refused(tmp_path, capsys) -> None:
    cert_pem, key_pem, _cert_der = self_signed()
    password = _password_file(tmp_path)
    with Router(cert_pem, key_pem, lambda body: ok([6])) as router:
        code, output = _run(
            [
                "verify",
                "--host", "127.0.0.1",
                "--port", str(router.port),
                "--pin", pin_of(cert_pem),
                "--password-file", str(password),
            ],
            capsys,
        )
    assert code == 1
    assert "FAIL" in output
    assert PASSWORD not in output


def test_verify_fails_on_a_wrong_pin(tmp_path, capsys) -> None:
    cert_pem, key_pem, _cert_der = self_signed()
    _other_pem, _other_key, other_der = self_signed()
    password = _password_file(tmp_path)
    from newton_mcp.adapters import openwrt_rpcd as rpcd

    with Router(cert_pem, key_pem, lambda body: _login_answer()) as router:
        code, output = _run(
            [
                "verify",
                "--host", "127.0.0.1",
                "--port", str(router.port),
                "--pin", rpcd.spki_pin(other_der),
                "--password-file", str(password),
            ],
            capsys,
        )
    assert code == 1
    assert "FAIL" in output


# ---- verify-refused --------------------------------------------------------


def test_verify_refused_passes_when_the_login_is_refused(tmp_path, capsys) -> None:
    cert_pem, key_pem, _cert_der = self_signed()
    password = _password_file(tmp_path)
    with Router(cert_pem, key_pem, lambda body: ok([6])) as router:
        code, output = _run(
            [
                "verify-refused",
                "--host", "127.0.0.1",
                "--port", str(router.port),
                "--pin", pin_of(cert_pem),
                "--password-file", str(password),
            ],
            capsys,
        )
    assert code == 0
    assert PASSWORD not in output


def test_verify_refused_fails_when_the_login_still_works(tmp_path, capsys) -> None:
    cert_pem, key_pem, _cert_der = self_signed()
    password = _password_file(tmp_path)
    with Router(cert_pem, key_pem, lambda body: _login_answer()) as router:
        code, output = _run(
            [
                "verify-refused",
                "--host", "127.0.0.1",
                "--port", str(router.port),
                "--pin", pin_of(cert_pem),
                "--password-file", str(password),
            ],
            capsys,
        )
    assert code == 1
    assert "FAIL" in output


# ---- the password file -----------------------------------------------------


def test_the_password_file_must_be_mode_0600(tmp_path, capsys) -> None:
    password = _password_file(tmp_path, mode=0o644)
    code, output = _run(
        [
            "verify",
            "--host", "127.0.0.1",
            "--port", "443",
            "--pin", pin_of(self_signed()[0]),
            "--password-file", str(password),
        ],
        capsys,
    )
    assert code == 1
    assert "0600" in output


def test_the_password_file_must_not_be_a_symlink(tmp_path, capsys) -> None:
    real = _password_file(tmp_path)
    link = tmp_path / "link"
    link.symlink_to(real)
    code, output = _run(
        [
            "verify",
            "--host", "127.0.0.1",
            "--port", "443",
            "--pin", pin_of(self_signed()[0]),
            "--password-file", str(link),
        ],
        capsys,
    )
    assert code == 1
    assert "symlink" in output or "regular file" in output


def test_the_password_file_must_exist(tmp_path, capsys) -> None:
    code, output = _run(
        [
            "verify",
            "--host", "127.0.0.1",
            "--port", "443",
            "--pin", pin_of(self_signed()[0]),
            "--password-file", str(tmp_path / "nope"),
        ],
        capsys,
    )
    assert code == 1
    assert output.strip()


def test_the_password_file_must_be_owned_by_the_caller(tmp_path, capsys, monkeypatch) -> None:
    password = _password_file(tmp_path)
    monkeypatch.setattr(os, "geteuid", lambda: password.stat().st_uid + 1)
    code, output = _run(
        [
            "verify",
            "--host", "127.0.0.1",
            "--port", "443",
            "--pin", pin_of(self_signed()[0]),
            "--password-file", str(password),
        ],
        capsys,
    )
    assert code == 1
    assert "owner" in output or "owned" in output


# ---- usage -----------------------------------------------------------------


def test_no_command_is_a_usage_error(capsys) -> None:
    code, output = _run([], capsys)
    assert code == 2
    assert output.strip()


def test_an_unknown_command_is_a_usage_error(capsys) -> None:
    code, output = _run(["frobnicate"], capsys)
    assert code == 2


def test_verify_without_a_host_is_a_usage_error(capsys) -> None:
    code, output = _run(["verify", "--port", "443"], capsys)
    assert code == 2


def test_a_bad_pin_argument_is_refused(tmp_path, capsys) -> None:
    password = _password_file(tmp_path)
    code, output = _run(
        [
            "verify",
            "--host", "127.0.0.1",
            "--port", "443",
            "--pin", "not-a-pin",
            "--password-file", str(password),
        ],
        capsys,
    )
    assert code == 1
    assert output.strip()


def test_the_password_never_reaches_the_screen(tmp_path, capsys) -> None:
    cert_pem, key_pem, _cert_der = self_signed()
    password = _password_file(tmp_path, text=PASSWORD)
    with Router(cert_pem, key_pem, lambda body: ok([6])) as router:
        code, output = _run(
            [
                "verify",
                "--host", "127.0.0.1",
                "--port", str(router.port),
                "--pin", pin_of(cert_pem),
                "--password-file", str(password),
            ],
            capsys,
        )
    assert code == 1
    assert PASSWORD not in output
    assert PASSWORD not in json.dumps(output)


# ---- the router's text never reaches the screen ------------


def test_an_error_code_with_the_password_in_it_never_reaches_the_screen(
    tmp_path, capsys
) -> None:
    cert_pem, key_pem, cert_der = self_signed()
    password = _password_file(tmp_path)
    answer = {
        "jsonrpc": "2.0",
        "id": 1,
        "error": {"code": PASSWORD, "message": PASSWORD},
    }
    with Router(
        cert_pem, key_pem, lambda body: (200, json.dumps(answer).encode())
    ) as router:
        code, output = _run(
            [
                "verify",
                "--host", "127.0.0.1",
                "--port", str(router.port),
                "--pin", pin_of(cert_pem),
                "--password-file", str(password),
            ],
            capsys,
        )
    assert code == 1
    assert PASSWORD not in output
    assert PASSWORD not in json.dumps(output)


def test_a_group_named_after_the_password_never_reaches_the_screen(
    tmp_path, capsys
) -> None:
    cert_pem, key_pem, cert_der = self_signed()
    password = _password_file(tmp_path)
    acls = {PASSWORD: ["read"]}
    with Router(cert_pem, key_pem, lambda body: _login_answer(acls)) as router:
        code, output = _run(
            [
                "verify",
                "--host", "127.0.0.1",
                "--port", str(router.port),
                "--pin", pin_of(cert_pem),
                "--password-file", str(password),
            ],
            capsys,
        )
    assert code == 1
    assert PASSWORD not in output
    assert PASSWORD not in json.dumps(output)

# ---- the codes the router sends (a1 r3, item 2) -----------------------------


def test_verify_never_writes_a_numeric_code_of_the_router_out(tmp_path, capsys) -> None:
    """The CLI prints the failure, but never the router's own number.

    A router that answers with a password as its code must not get
    that number on the screen: the code is written out by name, or as
    "unexpected code".
    """
    planted = "8675309431853271"
    cert_pem, key_pem, _cert_der = self_signed()
    password = _password_file(tmp_path)
    with Router(cert_pem, key_pem, lambda body: ok([int(planted)])) as router:
        code, output = _run(
            [
                "verify",
                "--host", "127.0.0.1",
                "--port", str(router.port),
                "--pin", pin_of(cert_pem),
                "--password-file", str(password),
            ],
            capsys,
        )
    assert code == 1
    assert planted not in output
    assert "unexpected code" in output
    assert not re.search(r"\d", output), output


def test_verify_refused_never_writes_a_numeric_code_of_the_router_out(
    tmp_path, capsys
) -> None:
    """The same for the proof that a removed login is refused."""
    planted = "8675309431853271"
    cert_pem, key_pem, _cert_der = self_signed()
    password = _password_file(tmp_path)
    with Router(cert_pem, key_pem, lambda body: ok([int(planted)])) as router:
        code, output = _run(
            [
                "verify-refused",
                "--host", "127.0.0.1",
                "--port", str(router.port),
                "--pin", pin_of(cert_pem),
                "--password-file", str(password),
            ],
            capsys,
        )
    assert code == 1
    assert planted not in output
    assert not re.search(r"\d", output), output


# ---- the owner finish that never reached the router ----------


class _FakeService:
    """The little of Newton's service the owner finish uses."""

    def __init__(self, state, devices):
        self.state = Path(state)
        self.devices = devices
        self.settled: list[tuple[str, bool]] = []

    def settle_approval(self, session_id, reached_router):
        self.settled.append((session_id, reached_router))


def test_the_owner_finish_that_never_reached_the_router_clears_the_run(
    tmp_path, monkeypatch
) -> None:
    """A run that never sent the script may be aborted.

    ``--reached no`` says the script never reached the router, so the
    run never started: the start of the run is cleared, and the plan
    can be aborted (the abort refuses a plan that already ran).
    """
    from newton_mcp import owner_records

    sid = "3f9a1c0be2d44b17a1c3d5e7f9012345"
    state = tmp_path / "state"
    (state / "plans").mkdir(parents=True)
    (state / "plans" / f"{sid}.json").write_text(
        json.dumps({"device": "r1"}), encoding="utf-8"
    )
    owner_records.write_run(state, sid, {"started_at": 1700000000.0})
    device = type("Device", (), {"name": "r1", "host": "10.1.2.3"})()
    service = _FakeService(state, {"r1": device})
    monkeypatch.setattr(rpcd_cli, "_service", lambda: service)

    args = type("Args", (), {"device": "r1", "session_id": sid, "reached": "no"})()
    code = rpcd_cli._owner_finish(args)

    assert code == rpcd_cli.EXIT_OK
    assert service.settled == [(sid, False)]
    assert "started_at" not in owner_records.read_run(state, sid)


# ---- the owner finish that never applied the change ----------


def test_the_owner_finish_of_a_change_that_was_never_applied_writes_no_receipt(
    tmp_path, monkeypatch
) -> None:
    """A change the router never took leaves no receipt.

    The read-back proved the change was never applied, so nothing is
    live on the router and there is nothing to undo: a receipt would
    claim otherwise (``undo_ready``).
    """
    from newton_mcp import change_receipt
    from newton_mcp import owner_verify

    sid = "3f9a1c0be2d44b17a1c3d5e7f9012345"
    state = tmp_path / "state"
    (state / "plans").mkdir(parents=True)
    (state / "plans" / f"{sid}.json").write_text(
        json.dumps({"device": "r1", "session_id": sid}), encoding="utf-8"
    )
    device = type("Device", (), {"name": "r1", "host": "10.1.2.3"})()
    service = _FakeService(state, {"r1": device})
    monkeypatch.setattr(rpcd_cli, "_service", lambda: service)
    monkeypatch.setattr(
        rpcd_cli.owner_backup, "load", lambda _state, _sid: object()
    )
    monkeypatch.setattr(
        rpcd_cli.owner_verify,
        "finish",
        lambda *args, **kwargs: owner_verify.Verdict(
            state=owner_verify.NOT_APPLIED,
            checks=(),
            deadline=1700000000.0,
        ),
    )

    args = type("Args", (), {"device": "r1", "session_id": sid, "reached": "yes"})()
    code = rpcd_cli._owner_finish(args)

    assert code == rpcd_cli.EXIT_OK
    receipts = state / change_receipt.RECEIPT_DIR
    written = sorted(receipts.glob("*.md")) if receipts.exists() else []
    assert written == [], "a change that was never applied leaves no receipt"
