"""the no-install transport, a pinned HTTPS JSON-RPC client to rpcd.

Everything here is local: the TLS server is a thread on 127.0.0.1 with a
certificate generated in the test, and no router is contacted.

The facts come from the lab measurement (lab-r1, OpenWrt 25.12.5):
  * the certificate uhttpd serves is DER, not PEM;
  * the SPKI sha256 (base64) is the pin;
  * a wrong pin must fail BEFORE any byte is sent;
  * an expired session, an unknown session and an ACL refusal all answer
    {"error": {"code": -32002}};
  * ubus answers [0, data] on success and [n] with n != 0 on refusal
    (4 NOT_FOUND, 5 NO_DATA, 6 PERMISSION_DENIED);
  * the router does not cap the login timeout (30 days were granted), so
    the client asks for a short one.
"""

from __future__ import annotations

import base64
import json
import re
from pathlib import Path

import pytest

from newton_mcp.adapters import openwrt_rpcd as rpcd
from rpcd_helpers import Raw, Router, ScriptedRouter, ok, pin_of, self_signed

# The sha256 of nothing.  It must never be a pin: a failed certificate
# read is an error, never a pin (measured on a lab router).
EMPTY_SHA256 = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="

PASSWORD = "synthetic-rpcd-password-9f3c"


# ---- helpers ---------------------------------------------------------------


def _session(session_id: str = "0123456789abcdef0123456789abcdef") -> rpcd.RpcdSession:
    return rpcd.RpcdSession(
        id=session_id, expires_at=0.0, acls={}, timeout_s=30
    )


# ---- the pin ---------------------------------------------------------------


def test_der_and_pem_give_the_same_pin() -> None:
    cert_pem, _key_pem, cert_der = self_signed()
    assert rpcd.spki_pin(cert_der) == rpcd.spki_pin(cert_pem)
    assert rpcd.spki_pin(cert_der) == pin_of(cert_pem)


def test_the_pin_is_44_base64_characters_of_32_bytes() -> None:
    _cert_pem, _key_pem, cert_der = self_signed()
    pin = rpcd.spki_pin(cert_der)
    assert len(pin) == 44
    assert len(base64.b64decode(pin, validate=True)) == 32


def test_an_empty_certificate_raises() -> None:
    with pytest.raises(rpcd.RpcdError):
        rpcd.spki_pin(b"")
    with pytest.raises(rpcd.RpcdError):
        rpcd.spki_pin(b"   \n")


def test_garbage_raises() -> None:
    with pytest.raises(rpcd.RpcdError):
        rpcd.spki_pin(b"not a certificate at all")


def test_more_than_one_certificate_raises() -> None:
    cert_pem, _key_pem, _cert_der = self_signed()
    with pytest.raises(rpcd.RpcdError):
        rpcd.spki_pin(cert_pem + cert_pem)


def test_the_pin_is_never_the_sha256_of_nothing() -> None:
    _cert_pem, _key_pem, cert_der = self_signed()
    assert rpcd.spki_pin(cert_der) != EMPTY_SHA256
    with pytest.raises(rpcd.RpcdError):
        rpcd.spki_pin(b"")


def test_the_install_set_keeps_cryptography() -> None:
    """The pin needs ``cryptography``; the lock file must keep it."""
    lock = Path(__file__).resolve().parents[1] / "requirements.lock"
    text = lock.read_text(encoding="utf-8")
    assert re.search(r"^cryptography==", text, re.MULTILINE), (
        "mcp/requirements.lock must pin cryptography: the no-install "
        "transport computes the SPKI pin with it"
    )


# ---- the client ------------------------------------------------------------


def test_the_client_posts_json_rpc_and_returns_the_data(tmp_path) -> None:
    cert_pem, key_pem, cert_der = self_signed()
    seen: list[dict] = []

    def reply(body: bytes):
        seen.append(json.loads(body))
        return ok([0, {"board_name": "lab-r1"}])

    with Router(cert_pem, key_pem, reply) as router:
        client = rpcd.RpcdClient("127.0.0.1", router.port, rpcd.spki_pin(cert_der))
        answer = client.call(_session(), "system", "board", {})

    assert answer == {"board_name": "lab-r1"}
    assert seen[0]["jsonrpc"] == "2.0"
    assert seen[0]["method"] == "call"
    assert seen[0]["params"][1:] == ["system", "board", {}]
    assert isinstance(seen[0]["id"], int)


def test_a_result_without_data_is_an_empty_object(tmp_path) -> None:
    cert_pem, key_pem, cert_der = self_signed()
    with Router(cert_pem, key_pem, lambda body: ok([0])) as router:
        client = rpcd.RpcdClient("127.0.0.1", router.port, rpcd.spki_pin(cert_der))
        assert client.call(_session(), "uci", "apply", {}) == {}


def test_a_wrong_pin_sends_nothing() -> None:
    cert_pem, key_pem, cert_der = self_signed()
    other_pin = rpcd.spki_pin(self_signed()[2])
    with Router(cert_pem, key_pem, lambda body: ok([0, {}])) as router:
        client = rpcd.RpcdClient("127.0.0.1", router.port, other_pin)
        with pytest.raises(rpcd.RpcdPinMismatch):
            client.call(_session(), "system", "board", {})
        # the router never saw a request byte
        assert router.received == []


def test_a_pin_mismatch_is_a_transport_error_that_was_not_sent() -> None:
    cert_pem, key_pem, cert_der = self_signed()
    other_pin = rpcd.spki_pin(self_signed()[2])
    with Router(cert_pem, key_pem, lambda body: ok([0, {}])) as router:
        client = rpcd.RpcdClient("127.0.0.1", router.port, other_pin)
        with pytest.raises(rpcd.RpcdTransportError) as caught:
            client.call(_session(), "system", "board", {})
    assert caught.value.sent is False


def test_a_redirect_is_refused() -> None:
    cert_pem, key_pem, cert_der = self_signed()

    def reply(body: bytes):
        return 302, b"{}"

    with Router(cert_pem, key_pem, reply) as router:
        client = rpcd.RpcdClient("127.0.0.1", router.port, rpcd.spki_pin(cert_der))
        with pytest.raises(rpcd.RpcdTransportError):
            client.call(_session(), "system", "board", {})


def test_a_non_200_status_is_refused() -> None:
    cert_pem, key_pem, cert_der = self_signed()
    with Router(cert_pem, key_pem, lambda body: (500, b"{}")) as router:
        client = rpcd.RpcdClient("127.0.0.1", router.port, rpcd.spki_pin(cert_der))
        with pytest.raises(rpcd.RpcdTransportError):
            client.call(_session(), "system", "board", {})


def test_an_oversized_body_is_refused() -> None:
    cert_pem, key_pem, cert_der = self_signed()
    payload = b"x" * (rpcd.MAX_BODY + 1)
    with Router(cert_pem, key_pem, lambda body: (200, payload)) as router:
        client = rpcd.RpcdClient("127.0.0.1", router.port, rpcd.spki_pin(cert_der))
        with pytest.raises(rpcd.RpcdTransportError):
            client.call(_session(), "system", "board", {})


def test_an_access_denied_answer_is_its_own_error() -> None:
    cert_pem, key_pem, cert_der = self_signed()
    answer = {"jsonrpc": "2.0", "id": 1, "error": {"code": -32002, "message": "Access denied"}}
    with Router(cert_pem, key_pem, lambda body: (200, json.dumps(answer).encode())) as router:
        client = rpcd.RpcdClient("127.0.0.1", router.port, rpcd.spki_pin(cert_der))
        with pytest.raises(rpcd.RpcdAccessDenied) as caught:
            client.call(_session(), "system", "board", {})
    message = str(caught.value)
    assert "denied" in message
    assert "expired" in message


def test_a_refused_call_keeps_the_ubus_code_and_name() -> None:
    cert_pem, key_pem, cert_der = self_signed()
    for code, name in ((4, "NOT_FOUND"), (5, "NO_DATA"), (6, "PERMISSION_DENIED")):
        with Router(cert_pem, key_pem, lambda body, c=code: ok([c])) as router:
            client = rpcd.RpcdClient("127.0.0.1", router.port, rpcd.spki_pin(cert_der))
            with pytest.raises(rpcd.RpcdCallFailed) as caught:
                client.call(_session(), "uci", "get", {})
            assert caught.value.code == code
            assert name in str(caught.value)


def test_the_login_uses_the_anonymous_session_id_and_a_bounded_timeout() -> None:
    cert_pem, key_pem, cert_der = self_signed()
    seen: list[dict] = []

    def reply(body: bytes):
        request = json.loads(body)
        seen.append(request)
        return ok([
            0,
            {
                "ubus_rpc_session": "0123456789abcdef0123456789abcdef",
                "ubus_rpc_session_expiry": 30,
                "acls": {"access-group": {"luci-base": ["read", "write"]}},
            },
        ])

    with Router(cert_pem, key_pem, reply) as router:
        client = rpcd.RpcdClient("127.0.0.1", router.port, rpcd.spki_pin(cert_der))
        session = client.login("newton", PASSWORD, 30)

    assert seen[0]["params"][0] == "0" * 32
    assert seen[0]["params"][1:3] == ["session", "login"]
    assert seen[0]["params"][3]["timeout"] == 30
    assert session.id == "0123456789abcdef0123456789abcdef"
    assert session.acls["access-group"]["luci-base"] == ["read", "write"]
    assert session.expires_at > 0


def test_the_login_refuses_an_unbounded_timeout() -> None:
    cert_pem, key_pem, cert_der = self_signed()
    with Router(cert_pem, key_pem, lambda body: ok([0, {}])) as router:
        client = rpcd.RpcdClient("127.0.0.1", router.port, rpcd.spki_pin(cert_der))
        for bad in (0, -1, 901, 30 * 24 * 60 * 60, True, 30.5, "30"):
            with pytest.raises(rpcd.RpcdError):
                client.login("newton", PASSWORD, bad)


def test_the_session_repr_never_shows_the_id() -> None:
    session = _session("f" * 32)
    assert "f" * 32 not in repr(session)
    assert "f" * 32 not in str(session)
    assert session.id not in repr(session)


def test_the_password_never_appears_in_an_exception_or_a_repr() -> None:
    cert_pem, key_pem, cert_der = self_signed()
    denied = {
        "jsonrpc": "2.0",
        "id": 1,
        "error": {"code": -32002, "message": "Access denied"},
    }
    failures = [
        (lambda c: c.call(_session(), "system", "board", {}), (200, json.dumps(denied).encode())),
        (lambda c: c.call(_session(), "system", "board", {}), ok([6])),
        (lambda c: c.call(_session(), "system", "board", {}), (302, b"{}")),
        (lambda c: c.login("newton", PASSWORD, 30), ok([6])),
    ]
    for action, reply in failures:
        with Router(cert_pem, key_pem, lambda body, r=reply: r) as router:
            client = rpcd.RpcdClient("127.0.0.1", router.port, rpcd.spki_pin(cert_der))
            with pytest.raises(rpcd.RpcdError) as caught:
                action(client)
            text = str(caught.value) + repr(caught.value)
            assert PASSWORD not in text
    with Router(cert_pem, key_pem, lambda body: ok([0, {}])) as router:
        client = rpcd.RpcdClient("127.0.0.1", router.port, rpcd.spki_pin(cert_der))
        creds = rpcd.RpcdCredentials(username="newton", password=PASSWORD)
        assert PASSWORD not in repr(creds)
        assert PASSWORD not in str(creds)


def test_the_client_refuses_a_url_that_is_not_https() -> None:
    with pytest.raises(rpcd.RpcdError):
        rpcd.RpcdClient("127.0.0.1", 443, "not-a-pin")
    with pytest.raises(rpcd.RpcdError):
        rpcd.RpcdClient("127.0.0.1", 0, pin_of(self_signed()[0]))
    with pytest.raises(rpcd.RpcdError):
        rpcd.RpcdClient("http://127.0.0.1", 443, pin_of(self_signed()[0]))


# ---- the codes the router sends (a1 r3, item 2) -----------------------------


#: A password a hostile router plants as its own code.
PLANTED_PASSWORD = "8675309431853271"


def test_the_known_codes_are_named() -> None:
    """Only the codes Newton knows are named; the rest is one phrase."""
    assert rpcd.code_name(0) == "OK"
    assert rpcd.code_name(1) == "INVALID_COMMAND"
    assert rpcd.code_name(2) == "INVALID_ARGUMENT"
    assert rpcd.code_name(3) == "METHOD_NOT_FOUND"
    assert rpcd.code_name(4) == "NOT_FOUND"
    assert rpcd.code_name(5) == "NO_DATA"
    assert rpcd.code_name(6) == "PERMISSION_DENIED"
    assert rpcd.code_name(7) == "TIMEOUT"
    assert rpcd.code_name(8) == "NOT_SUPPORTED"
    assert rpcd.code_name(9) == "UNKNOWN_ERROR"
    assert rpcd.code_name(10) == "CONNECTION_FAILED"
    assert rpcd.code_name(-32700) == "PARSE_ERROR"
    assert rpcd.code_name(-32600) == "INVALID_REQUEST"
    assert rpcd.code_name(-32601) == "METHOD_NOT_FOUND"
    assert rpcd.code_name(-32602) == "INVALID_PARAMS"
    assert rpcd.code_name(-32603) == "INTERNAL_ERROR"
    assert rpcd.code_name(-32000) == "SERVER_ERROR"
    assert rpcd.code_name(-32001) == "SERVER_ERROR"
    assert rpcd.code_name(-32002) == "ACCESS_DENIED"
    # a code Newton does not know is never written out
    assert rpcd.code_name(int(PLANTED_PASSWORD)) == "unexpected code"
    assert not re.search(r"\d", rpcd.code_name(int(PLANTED_PASSWORD)))


def test_an_error_code_that_is_a_password_is_never_written_out() -> None:
    """A router that plants the password as its error code leaks nothing.

    The error code is the router's own text.  Only the codes Newton
    knows by name are written out; every other value is "unexpected
    code", with no digits at all.
    """
    cert_pem, key_pem, cert_der = self_signed()
    answer = {
        "jsonrpc": "2.0",
        "id": 1,
        "error": {"code": int(PLANTED_PASSWORD)},
    }
    with Router(
        cert_pem, key_pem, lambda body: (200, json.dumps(answer).encode())
    ) as router:
        client = rpcd.RpcdClient("127.0.0.1", router.port, rpcd.spki_pin(cert_der))
        with pytest.raises(rpcd.RpcdError) as caught:
            client.call(_session(), "system", "board", {})
    text = str(caught.value) + repr(caught.value)
    assert PLANTED_PASSWORD not in text
    assert "unexpected code" in text
    assert not re.search(r"\d", text), text


def test_a_result_code_that_is_a_password_is_never_written_out() -> None:
    """The same for the result code of an ubus call.

    The code itself is kept for the program logic (``code``); only the
    text is restricted.
    """
    cert_pem, key_pem, cert_der = self_signed()
    with Router(cert_pem, key_pem, lambda body: ok([int(PLANTED_PASSWORD)])) as router:
        client = rpcd.RpcdClient("127.0.0.1", router.port, rpcd.spki_pin(cert_der))
        with pytest.raises(rpcd.RpcdCallFailed) as caught:
            client.call(_session(), "uci", "get", {})
    text = str(caught.value) + repr(caught.value)
    assert PLANTED_PASSWORD not in text
    assert "unexpected code" in text
    assert not re.search(r"\d", text), text
    # the code is still there for the program logic
    assert caught.value.code == int(PLANTED_PASSWORD)


def test_a_known_code_is_named_and_keeps_no_digits() -> None:
    """A code Newton knows is written out by name, not by number."""
    cert_pem, key_pem, cert_der = self_signed()
    with Router(cert_pem, key_pem, lambda body: ok([6])) as router:
        client = rpcd.RpcdClient("127.0.0.1", router.port, rpcd.spki_pin(cert_der))
        with pytest.raises(rpcd.RpcdCallFailed) as caught:
            client.call(_session(), "uci", "get", {})
    text = str(caught.value) + repr(caught.value)
    assert "PERMISSION_DENIED" in text
    assert not re.search(r"\d", text), text
    assert caught.value.code == 6


# ---- the group lists -------------------------------------------------------


def test_the_group_lists_are_pinned() -> None:
    assert rpcd.READ_GROUPS == (
        "luci-base",
        "luci-base-network-status",
        "luci-mod-network-config",
        "luci-mod-network-dhcp",
        "luci-mod-network-diagnostics",
        "luci-mod-status-index",
        "luci-mod-status-logs",
    )
    assert rpcd.WRITE_GROUPS == ("luci-base", "luci-mod-network-config")
    assert rpcd.RPCD_USER == "newton"
    assert rpcd.RPCD_SECTION == "newton"
    assert rpcd.OWNER_TAG == "newton-mcp"


def test_the_never_list_holds_the_dangerous_groups() -> None:
    # every luci-mod-system-* group of the 25.12 stock ACL set (the
    # list the lab measurement derived from lab-r1's /usr/share/rpcd/acl.d)
    for group in (
        "luci-mod-system-config",
        "luci-mod-system-cron",
        "luci-mod-system-flash",
        "luci-mod-system-init",
        "luci-mod-system-mounts",
        "luci-mod-system-reboot",
        "luci-mod-system-repokeys",
        "luci-mod-system-ssh",
        "luci-mod-system-uhttpd",
    ):
        assert group in rpcd.NEVER_GROUPS, group
    for group in (
        "luci-app-package-manager",
        "luci-app-attendedsysupgrade",
        "luci-app-firewall",
    ):
        assert group in rpcd.NEVER_GROUPS, group


def test_read_write_and_never_never_meet() -> None:
    assert not set(rpcd.READ_GROUPS) & set(rpcd.NEVER_GROUPS)
    assert not set(rpcd.WRITE_GROUPS) & set(rpcd.NEVER_GROUPS)


def test_every_luci_mod_system_group_is_never_granted() -> None:
    system_groups = [g for g in rpcd.NEVER_GROUPS if g.startswith("luci-mod-system-")]
    assert system_groups, "the never list must name the system groups"


# ---- check_acls ------------------------------------------------------------


def _acls(groups: dict[str, list[str]]) -> dict:
    return {"access-group": groups}


def test_check_acls_accepts_the_measured_answer() -> None:
    measured = {
        "luci-base": ["read", "write"],
        "luci-base-network-status": ["read"],
        "luci-mod-network-config": ["read", "write"],
        "luci-mod-network-dhcp": ["read"],
        "luci-mod-network-diagnostics": ["read"],
        "luci-mod-status-index": ["read"],
        "luci-mod-status-logs": ["read"],
    }
    assert rpcd.check_acls(_acls(measured)) == []


def test_check_acls_reports_a_missing_group() -> None:
    measured = {
        "luci-base": ["read", "write"],
        "luci-base-network-status": ["read"],
        "luci-mod-network-config": ["read", "write"],
        "luci-mod-network-dhcp": ["read"],
        "luci-mod-network-diagnostics": ["read"],
        "luci-mod-status-index": ["read"],
    }
    differences = rpcd.check_acls(_acls(measured))
    assert len(differences) == 1
    assert "luci-mod-status-logs" in differences[0]


def test_check_acls_reports_a_missing_permission() -> None:
    measured = {
        "luci-base": ["read"],
        "luci-base-network-status": ["read"],
        "luci-mod-network-config": ["read", "write"],
        "luci-mod-network-dhcp": ["read"],
        "luci-mod-network-diagnostics": ["read"],
        "luci-mod-status-index": ["read"],
        "luci-mod-status-logs": ["read"],
    }
    differences = rpcd.check_acls(_acls(measured))
    assert len(differences) == 1
    assert "luci-base" in differences[0]
    assert "write" in differences[0]


def test_check_acls_reports_an_extra_group() -> None:
    measured = {
        "luci-base": ["read", "write"],
        "luci-base-network-status": ["read"],
        "luci-mod-network-config": ["read", "write"],
        "luci-mod-network-dhcp": ["read"],
        "luci-mod-network-diagnostics": ["read"],
        "luci-mod-status-index": ["read"],
        "luci-mod-status-logs": ["read"],
        "luci-mod-system-ssh": ["read", "write"],
    }
    differences = rpcd.check_acls(_acls(measured))
    assert len(differences) == 1
    assert "luci-mod-system-ssh" in differences[0]


def test_check_acls_reports_an_extra_permission() -> None:
    measured = {
        "luci-base": ["read", "write", "exec"],
        "luci-base-network-status": ["read"],
        "luci-mod-network-config": ["read", "write"],
        "luci-mod-network-dhcp": ["read"],
        "luci-mod-network-diagnostics": ["read"],
        "luci-mod-status-index": ["read"],
        "luci-mod-status-logs": ["read"],
    }
    differences = rpcd.check_acls(_acls(measured))
    assert len(differences) == 1
    assert "luci-base" in differences[0]


def test_check_acls_reports_an_answer_without_the_access_group() -> None:
    differences = rpcd.check_acls({})
    assert differences


# ---- the router's text never reaches an error ----------------


def _assert_no_password(error: BaseException) -> None:
    text = str(error) + repr(error)
    assert PASSWORD not in text, text


def test_an_error_code_that_is_not_a_number_never_reaches_an_exception() -> None:
    """A router that reflects the password back must not put it in an error."""
    cert_pem, key_pem, cert_der = self_signed()
    answer = {
        "jsonrpc": "2.0",
        "id": 1,
        "error": {"code": PASSWORD, "message": PASSWORD},
    }
    with Router(
        cert_pem, key_pem, lambda body: (200, json.dumps(answer).encode())
    ) as router:
        client = rpcd.RpcdClient("127.0.0.1", router.port, rpcd.spki_pin(cert_der))
        with pytest.raises(rpcd.RpcdError) as caught:
            client.call(_session(), "system", "board", {})
    _assert_no_password(caught.value)


def test_a_malformed_status_line_never_reaches_an_exception() -> None:
    cert_pem, key_pem, cert_der = self_signed()
    broken = b"HTTP/1.1 " + PASSWORD.encode() + b"\r\n\r\n"

    def handler(obj: str, fn: str, args: dict):
        return Raw(broken)

    with ScriptedRouter(cert_pem, key_pem, handler) as router:
        client = rpcd.RpcdClient("127.0.0.1", router.port, rpcd.spki_pin(cert_der))
        with pytest.raises(rpcd.RpcdError) as caught:
            client.call(_session(), "system", "board", {})
    _assert_no_password(caught.value)


def test_a_result_code_that_is_not_a_number_never_reaches_an_exception() -> None:
    cert_pem, key_pem, cert_der = self_signed()
    answer = {"jsonrpc": "2.0", "id": 1, "result": [PASSWORD]}
    with Router(
        cert_pem, key_pem, lambda body: (200, json.dumps(answer).encode())
    ) as router:
        client = rpcd.RpcdClient("127.0.0.1", router.port, rpcd.spki_pin(cert_der))
        with pytest.raises(rpcd.RpcdError) as caught:
            client.call(_session(), "system", "board", {})
    _assert_no_password(caught.value)


def test_a_login_answer_with_a_password_in_it_never_reaches_an_exception() -> None:
    cert_pem, key_pem, cert_der = self_signed()
    answer = {
        "jsonrpc": "2.0",
        "id": 1,
        "result": [0, {"ubus_rpc_session": PASSWORD, "acls": {}}],
    }
    with Router(
        cert_pem, key_pem, lambda body: (200, json.dumps(answer).encode())
    ) as router:
        client = rpcd.RpcdClient("127.0.0.1", router.port, rpcd.spki_pin(cert_der))
        with pytest.raises(rpcd.RpcdError) as caught:
            client.login("newton", PASSWORD, 30)
    _assert_no_password(caught.value)


def test_a_refused_call_with_a_password_in_the_code_never_reaches_an_exception() -> None:
    cert_pem, key_pem, cert_der = self_signed()
    answer = {"jsonrpc": "2.0", "id": 1, "result": [PASSWORD]}
    with Router(
        cert_pem, key_pem, lambda body: (200, json.dumps(answer).encode())
    ) as router:
        client = rpcd.RpcdClient("127.0.0.1", router.port, rpcd.spki_pin(cert_der))
        with pytest.raises(rpcd.RpcdError) as caught:
            client.call(_session(), "system", "board", {})
    _assert_no_password(caught.value)


# ---- a body that stops in the middle ------------------------


def test_a_truncated_body_is_a_transport_error_that_was_sent() -> None:
    """The request went out: the answer may have been applied."""
    cert_pem, key_pem, cert_der = self_signed()

    def handler(obj: str, fn: str, args: dict):
        return [0, {}]

    with ScriptedRouter(
        cert_pem, key_pem, handler, truncate=("system.board",)
    ) as router:
        client = rpcd.RpcdClient("127.0.0.1", router.port, rpcd.spki_pin(cert_der))
        with pytest.raises(rpcd.RpcdTransportError) as caught:
            client.call(_session(), "system", "board", {})
    assert caught.value.sent is True
