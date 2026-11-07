"""the no-install transport leaves a receipt when the runner asks for one.

The lab runner hands every scenario command the path of a receipt file
(``NEWTON_LAB_RECEIPT``).  The one place that sends an rpcd call over
HTTPS appends one line per call that got an HTTP answer: the method
and nothing else -- no arguments, no secrets, no host names.  The runner
reads the file after every scenario and derives the access mode of the
run from those lines (ADR-021 point 1).

Everything here is local: the TLS server is a thread on 127.0.0.1 with
a certificate generated in the test, and no router is contacted.
"""

from __future__ import annotations

from newton_mcp.adapters import openwrt_rpcd as rpcd
from rpcd_helpers import Router, ok, self_signed

# a secret that must never reach the receipt file
SECRET = "s3cret-value-8f2a"


def _session(session_id: str = "0123456789abcdef0123456789abcdef") -> rpcd.RpcdSession:
    return rpcd.RpcdSession(id=session_id, expires_at=0.0, acls={}, timeout_s=30)


def _client(router, cert_der):
    return rpcd.RpcdClient("127.0.0.1", router.port, rpcd.spki_pin(cert_der))


def test_the_transport_leaves_a_receipt_when_the_runner_asks_for_one(
        tmp_path, monkeypatch) -> None:
    """A call that got an HTTP answer writes one line: the method."""
    receipt = tmp_path / "receipts.txt"
    monkeypatch.setenv(rpcd.RECEIPT_ENV, str(receipt))
    cert_pem, key_pem, cert_der = self_signed()
    with Router(cert_pem, key_pem, lambda body: ok([0, {"board_name": "lab-r1"}])) as router:
        answer = _client(router, cert_der).call(_session(), "system", "board", {})
    assert answer == {"board_name": "lab-r1"}
    assert receipt.read_text().splitlines() == ["rpcd system.board"]


def test_the_receipt_line_carries_no_arguments_and_no_secrets(
        tmp_path, monkeypatch) -> None:
    """The line names the method and nothing else: no arguments, no
    secret that travelled with the call."""
    receipt = tmp_path / "receipts.txt"
    monkeypatch.setenv(rpcd.RECEIPT_ENV, str(receipt))
    cert_pem, key_pem, cert_der = self_signed()
    with Router(cert_pem, key_pem, lambda body: ok([0, {}])) as router:
        _client(router, cert_der).call(
            _session(), "uci", "set",
            {"name": "wifi", "password": SECRET, "host": "192.0.2.9"})
    text = receipt.read_text()
    assert text.strip() == "rpcd uci.set", text
    assert SECRET not in text, text
    assert "192.0.2.9" not in text, text


def test_the_receipt_names_no_host_of_the_router(tmp_path, monkeypatch) -> None:
    """The host the client dialled is not in the line: the receipt says
    what ran, not where."""
    receipt = tmp_path / "receipts.txt"
    monkeypatch.setenv(rpcd.RECEIPT_ENV, str(receipt))
    cert_pem, key_pem, cert_der = self_signed()
    with Router(cert_pem, key_pem, lambda body: ok([0, {}])) as router:
        _client(router, cert_der).call(_session(), "uci", "get", {})
    text = receipt.read_text()
    assert "127.0.0.1" not in text, text
    assert str(router.port) not in text, text


def test_no_receipt_is_written_when_the_runner_asks_for_none(
        tmp_path, monkeypatch) -> None:
    """The variable is unset outside a lab run: the transport writes
    nothing and changes nothing."""
    monkeypatch.delenv(rpcd.RECEIPT_ENV, raising=False)
    cert_pem, key_pem, cert_der = self_signed()
    with Router(cert_pem, key_pem, lambda body: ok([0, {"a": 1}])) as router:
        answer = _client(router, cert_der).call(_session(), "system", "board", {})
    assert answer == {"a": 1}
    assert list(tmp_path.iterdir()) == []


def test_a_call_that_never_reached_the_router_leaves_no_receipt(
        tmp_path, monkeypatch) -> None:
    """A wrong pin fails before a byte is sent: the transport never ran,
    so there is nothing to report."""
    receipt = tmp_path / "receipts.txt"
    monkeypatch.setenv(rpcd.RECEIPT_ENV, str(receipt))
    cert_pem, key_pem, cert_der = self_signed()
    other_pin = rpcd.spki_pin(self_signed()[2])
    with Router(cert_pem, key_pem, lambda body: ok([0, {}])) as router:
        client = rpcd.RpcdClient("127.0.0.1", router.port, other_pin)
        try:
            client.call(_session(), "system", "board", {})
        except rpcd.RpcdPinMismatch:
            pass
        else:
            raise AssertionError("the wrong pin must fail")
    assert not receipt.exists()


def test_a_receipt_that_cannot_be_written_never_breaks_the_call(
        tmp_path, monkeypatch) -> None:
    """A receipt file that cannot be written is not an error the call
    may fail on: the change still goes through."""
    receipt = tmp_path / "receipts.txt"
    receipt.mkdir()
    monkeypatch.setenv(rpcd.RECEIPT_ENV, str(receipt))
    cert_pem, key_pem, cert_der = self_signed()
    with Router(cert_pem, key_pem, lambda body: ok([0, {"board_name": "lab-r1"}])) as router:
        answer = _client(router, cert_der).call(_session(), "system", "board", {})
    assert answer == {"board_name": "lab-r1"}


def test_a_login_is_a_receipt_too(tmp_path, monkeypatch) -> None:
    """The login is an rpcd call over HTTPS as well: it leaves its own
    line, so a no-install run is told about the transport even when the
    login is the first thing that happens."""
    receipt = tmp_path / "receipts.txt"
    monkeypatch.setenv(rpcd.RECEIPT_ENV, str(receipt))
    cert_pem, key_pem, cert_der = self_signed()

    def reply(body: bytes):
        return ok([0, {"ubus_rpc_session": _session().id, "acls": {}}])

    with Router(cert_pem, key_pem, reply) as router:
        session = _client(router, cert_der).login("newton", SECRET, 30)
    assert session.id == _session().id
    assert receipt.read_text().splitlines() == ["rpcd session.login"]
