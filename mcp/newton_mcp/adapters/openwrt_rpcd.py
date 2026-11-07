"""The no-install transport: HTTPS JSON-RPC to the router's own rpcd.

ADR-021 point 2.  In the no-install mode Newton puts nothing on the
router: it talks to the router's own web API (uhttpd's ``/ubus``) as a
limited rpcd user.  The transport therefore has to be careful on its
own:

  * HTTPS only.  The URL is built here (``https://host:port/ubus``), so
    plain HTTP cannot even be asked for.
  * The certificate is pinned by the sha256 of its SubjectPublicKeyInfo.
    The pin is read over the admin lane, never from the endpoint, and it
    is checked BEFORE a single byte is sent.
  * Redirects are never followed.
  * The password never appears in an exception, a log line or a repr.

Every fact here comes from the lab measurement (lab-r1, OpenWrt 25.12.5,
2026-10-28): the certificate uhttpd serves is DER, not PEM; a wrong pin
must fail before anything is sent; an expired session, an unknown
session and an ACL refusal all answer ``{"error": {"code": -32002}}``;
ubus answers ``[0, data]`` on success and ``[n]`` with n != 0 on refusal
(4 NOT_FOUND, 5 NO_DATA, 6 PERMISSION_DENIED); and the router does not
cap the login timeout (30 days were granted), so the client asks for a
short one.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import http.client
import json
import os
import re
import socket
import ssl
import time
from dataclasses import dataclass
from typing import Any, Mapping

from .ssh_cli import HOST_RE

# ---- the group lists: the single place they live ---------------------------
# Setup reads them through the ``newton-rpcd groups`` command, so
# the router's login section and Newton's expectations cannot drift.

#: The groups Newton asks to read with.
READ_GROUPS: tuple[str, ...] = (
    "luci-base",
    "luci-base-network-status",
    "luci-mod-network-config",
    "luci-mod-network-dhcp",
    "luci-mod-network-diagnostics",
    "luci-mod-status-index",
    "luci-mod-status-logs",
)

#: The groups Newton asks to write with.
WRITE_GROUPS: tuple[str, ...] = (
    "luci-base",
    "luci-mod-network-config",
)

#: The rpcd user Newton logs in as, and the UCI section setup adds.
RPCD_USER = "newton"
RPCD_SECTION = "newton"

#: The marker setup writes into the login section, so an uninstall can
#: tell Newton's own section from one the owner made.
OWNER_TAG = "newton-mcp"

#: The groups Newton never asks for.  Every ``luci-mod-system-*`` group
#: is on the list (root password, init scripts, reboot, flash, ssh,
#: uhttpd, cron, mounts, repokeys); the package manager and the firmware
#: upgrader are on it; and so is luci-app-firewall, whose write grant
#: includes ``file write /etc/firewall.user``.
NEVER_GROUPS: tuple[str, ...] = (
    "luci-mod-system-config",
    "luci-mod-system-cron",
    "luci-mod-system-flash",
    "luci-mod-system-init",
    "luci-mod-system-mounts",
    "luci-mod-system-reboot",
    "luci-mod-system-repokeys",
    "luci-mod-system-ssh",
    "luci-mod-system-uhttpd",
    "luci-app-package-manager",
    "luci-app-attendedsysupgrade",
    "luci-app-firewall",
)

#: The session id a login starts from: the all-zeros anonymous id.
ANONYMOUS_SESSION_ID = "0" * 32

#: The largest answer Newton reads.  A router that answers with more is
#: refused, not truncated.
MAX_BODY = 1024 * 1024

#: The variable the lab runner sets: the file this transport writes its
#: receipt lines into.  It is unset outside a lab run, so nothing is
#: written and nothing changes.
RECEIPT_ENV = "NEWTON_LAB_RECEIPT"

#: The longest session Newton asks for.  The router does not cap it, so
#: the client does.
LOGIN_TIMEOUT_MAX = 900

SESSION_ID_RE = re.compile(r"^[0-9a-f]{32}$")
PIN_RE = re.compile(r"^[A-Za-z0-9+/]{43}=$")

#: The ubus result codes Newton knows by name.
UBUS_NAMES: dict[int, str] = {
    0: "OK",
    1: "INVALID_COMMAND",
    2: "INVALID_ARGUMENT",
    3: "METHOD_NOT_FOUND",
    4: "NOT_FOUND",
    5: "NO_DATA",
    6: "PERMISSION_DENIED",
    7: "TIMEOUT",
    8: "NOT_SUPPORTED",
    9: "UNKNOWN_ERROR",
    10: "CONNECTION_FAILED",
}

#: The JSON-RPC error codes Newton knows by name.  -32000 and -32001
#: are in the server-error range of the JSON-RPC spec; -32002 is the
#: answer the router gives for a refused session (measured on lab-r1:
#: an expired session, an unknown session and an ACL refusal).
JSONRPC_NAMES: dict[int, str] = {
    -32700: "PARSE_ERROR",
    -32600: "INVALID_REQUEST",
    -32601: "METHOD_NOT_FOUND",
    -32602: "INVALID_PARAMS",
    -32603: "INTERNAL_ERROR",
    -32000: "SERVER_ERROR",
    -32001: "SERVER_ERROR",
    -32002: "ACCESS_DENIED",
}

#: What a code Newton does not know is called.  The phrase has no
#: digits: the value came from the router, and a router that answers
#: with a password as its own code must not get that password on the
#: screen, in a message or in a repr.
UNEXPECTED_CODE = "unexpected code"


def code_name(code: object) -> str:
    """The name of a code the router sent, or "unexpected code".

    This is the one place where a router's own code becomes text.  Only
    the codes Newton knows by name are written out; every other value
    is the one phrase above, which holds no digits.  The code itself
    is kept on the exception (``code``) for the program logic.
    """
    if isinstance(code, bool) or not isinstance(code, int):
        return UNEXPECTED_CODE
    name = UBUS_NAMES.get(code)
    if name is None:
        name = JSONRPC_NAMES.get(code)
    if name is None:
        return UNEXPECTED_CODE
    return name


# ---- errors ----------------------------------------------------------------


class RpcdError(Exception):
    """Any failure of the no-install transport."""


class RpcdTransportError(RpcdError):
    """The router could not be reached, or answered something else.

    ``sent`` says whether the request had already gone out when the
    failure happened.  The transaction engine needs that: a lost answer
    to an apply may still have applied the change, a failure before the
    request went out certainly did not.
    """

    def __init__(self, message: str, *, sent: bool = False) -> None:
        super().__init__(message)
        self.sent = sent


class RpcdPinMismatch(RpcdTransportError):
    """The certificate's SPKI is not the pinned one: nothing was sent."""


class RpcdAccessDenied(RpcdError):
    """The router refused the session."""


class RpcdCallFailed(RpcdError):
    """The ubus call itself failed; ``code`` is the router's own code.

    The code is the router's own text, so it is kept for the program
    logic but only its name (or "unexpected code") is ever written
    out.
    """

    def __init__(self, code: int) -> None:
        if isinstance(code, bool) or not isinstance(code, int):
            # The router's own text never goes into an error: a router
            # that reflects the password back must not put it on the
            # screen, in a message or in a repr.
            super().__init__("rpcd call failed: the router's code is not a number")
            self.code = -1
            return
        super().__init__(f"rpcd call failed: {code_name(code)}")
        self.code = code


# ---- the session and the credentials ---------------------------------------


@dataclass
class RpcdSession:
    """One rpcd session.

    ``expires_at`` is computed locally (the login time plus the timeout
    Newton asked for); the router's own expiry is not trusted.  The
    repr never shows the session id.
    """

    id: str
    expires_at: float
    acls: dict[str, Any]
    timeout_s: int
    spent: bool = False

    def mark_spent(self) -> None:
        """Spend the session: it must not be used again."""
        self.spent = True

    def __repr__(self) -> str:
        return (
            f"RpcdSession(id=<hidden>, expires_at={self.expires_at:.0f}, "
            f"timeout_s={self.timeout_s}, spent={self.spent})"
        )


@dataclass(frozen=True)
class RpcdCredentials:
    """The rpcd user's name and password.  The repr hides the password."""

    username: str = RPCD_USER
    password: str = ""

    def __repr__(self) -> str:
        return f"RpcdCredentials(username={self.username!r}, password=<hidden>)"


# ---- the pin ---------------------------------------------------------------


def is_valid_pin(value: object) -> bool:
    """True when the value is the base64 sha256 of a 32-byte digest."""
    if not isinstance(value, str) or PIN_RE.fullmatch(value) is None:
        return False
    try:
        return len(base64.b64decode(value, validate=True)) == 32
    except (binascii.Error, ValueError):
        return False


def _load_certificate(data: bytes):
    try:
        from cryptography import x509
    except ImportError as exc:  # pragma: no cover - the lock file keeps it
        raise RpcdError(
            "the cryptography package is needed to compute the certificate pin"
        ) from exc
    if b"-----BEGIN CERTIFICATE-----" in data:
        try:
            certificates = x509.load_pem_x509_certificates(data)
        except Exception:
            raise RpcdError("the PEM certificate cannot be read") from None
        if len(certificates) != 1:
            raise RpcdError(
                f"expected exactly one certificate, found {len(certificates)}"
            )
        return certificates[0]
    try:
        return x509.load_der_x509_certificate(data)
    except Exception:
        raise RpcdError(
            "the certificate cannot be read (neither DER nor PEM)"
        ) from None


def spki_pin(cert_bytes: bytes) -> str:
    """The pin of a certificate: the base64 sha256 of its SPKI DER.

    A DER certificate and the same certificate in PEM give the same
    pin.  Empty input, garbage and a bundle of more than one certificate
    are errors: a failed certificate read must never become a pin (the
    sha256 of nothing is a real value, and a router with no certificate
    would match it).
    """
    if not isinstance(cert_bytes, (bytes, bytearray)):
        raise RpcdError("the certificate must be bytes")
    data = bytes(cert_bytes)
    if not data.strip():
        raise RpcdError("the certificate is empty: refusing to pin nothing")
    certificate = _load_certificate(data)
    from cryptography.hazmat.primitives import serialization

    spki = certificate.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(hashlib.sha256(spki).digest()).decode("ascii")


# ---- the acl check ---------------------------------------------------------


def expected_groups() -> dict[str, set[str]]:
    """The groups Newton asks for, with the permissions it asks for."""
    groups: dict[str, set[str]] = {}
    for group in READ_GROUPS:
        groups.setdefault(group, set()).add("read")
    for group in WRITE_GROUPS:
        groups.setdefault(group, set()).add("write")
    return groups


def check_acls(acls: Mapping[str, Any]) -> list[str]:
    """The differences between a login answer's groups and Newton's lists.

    The login answer's ``acls["access-group"]`` is the authoritative
    list of what the router granted.  Every READ group must have
    "read", every WRITE group must have "write", and no other group may
    be there.
    """
    differences: list[str] = []
    if not isinstance(acls, Mapping):
        return ["the login answer carries no acl list"]
    groups = acls.get("access-group")
    if not isinstance(groups, Mapping):
        return ["the login answer has no access-group list"]
    expected = expected_groups()
    for group, permissions in sorted(expected.items()):
        granted = groups.get(group)
        if granted is None:
            differences.append(f"group {group} is missing")
            continue
        if isinstance(granted, str):
            granted = [granted]
        if not isinstance(granted, (list, tuple, set)):
            differences.append(f"group {group} has an unreadable permission list")
            continue
        held = {str(item) for item in granted}
        for permission in sorted(permissions - held):
            differences.append(f"group {group} is missing {permission}")
        for permission in sorted(held - permissions):
            differences.append(
                f"group {group} has the unexpected permission {permission}"
            )
    for group in sorted(str(name) for name in groups):
        if group not in expected:
            differences.append(f"group {group} is not one of Newton's groups")
    return differences


# ---- the client ------------------------------------------------------------


def note_rpcd_call(obj: str, fn: str) -> None:
    """Append one line to the run's receipt file, when there is one.

    The receipt is how the lab runner learns that the HTTPS rpcd
    transport ran (ADR-021 point 1): one line per call that got an
    HTTP answer, naming the method and nothing else -- no arguments,
    no secrets, no host names.  The variable is unset outside a lab
    run, so nothing is written and nothing changes; a file that cannot
    be written is never a reason to fail the call.
    """
    path = os.environ.get(RECEIPT_ENV)
    if not path:
        return
    try:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write("rpcd %s.%s\n" % (obj, fn))
    except Exception:
        # the receipt is evidence, never a reason to break a change:
        # every write error is swallowed here
        return


class RpcdClient:
    """A pinned HTTPS JSON-RPC client for the router's own ``/ubus``."""

    def __init__(
        self, host: str, port: int, pin: str, timeout_s: float = 20
    ) -> None:
        if not isinstance(host, str) or HOST_RE.fullmatch(host) is None:
            raise RpcdError("the host fails the hostname grammar")
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise RpcdError("the port must be 1..65535")
        if not is_valid_pin(pin):
            raise RpcdError(
                "the pin must be the base64 sha256 of the certificate's SPKI "
                "(44 characters)"
            )
        if (
            isinstance(timeout_s, bool)
            or not isinstance(timeout_s, (int, float))
            or timeout_s <= 0
        ):
            raise RpcdError("the timeout must be a positive number of seconds")
        self.host = host
        self.port = port
        self.pin = pin
        self.timeout_s = float(timeout_s)
        self._next_id = 0

    @property
    def url(self) -> str:
        """The endpoint.  There is no way to ask for plain HTTP."""
        return f"https://{self.host}:{self.port}/ubus"

    # -- the public calls ----------------------------------------------------

    def login(self, username: str, password: str, timeout_s: int) -> RpcdSession:
        """Log in and keep the session.

        The session starts from the all-zeros anonymous id.  The
        timeout is required and bounded: the router does not cap it (30
        days were granted in the lab), so the client does.
        """
        if not isinstance(username, str) or not username:
            raise RpcdError("the username must be a non-empty string")
        if not isinstance(password, str) or not password:
            raise RpcdError("the password must be a non-empty string")
        if (
            isinstance(timeout_s, bool)
            or not isinstance(timeout_s, int)
            or not 1 <= timeout_s <= LOGIN_TIMEOUT_MAX
        ):
            raise RpcdError(
                f"the timeout must be between 1 and {LOGIN_TIMEOUT_MAX} seconds"
            )
        answer = self._rpc(
            ANONYMOUS_SESSION_ID,
            "session",
            "login",
            {"username": username, "password": password, "timeout": timeout_s},
        )
        if not isinstance(answer, Mapping):
            raise RpcdError("the router's login answer is not an object")
        session_id = answer.get("ubus_rpc_session")
        if not isinstance(session_id, str) or SESSION_ID_RE.fullmatch(session_id) is None:
            raise RpcdError("the router did not return a session id")
        acls = answer.get("acls")
        if not isinstance(acls, dict):
            acls = {}
        return RpcdSession(
            id=session_id,
            expires_at=time.time() + timeout_s,
            acls=acls,
            timeout_s=timeout_s,
        )

    def call(
        self,
        session: RpcdSession,
        obj: str,
        fn: str,
        args: Mapping[str, Any] | None = None,
    ) -> Any:
        """One ubus call in a session."""
        if session.spent:
            raise RpcdError("this rpcd session is spent and must not be used again")
        return self._rpc(session.id, obj, fn, args)

    # -- the wire ------------------------------------------------------------

    def _rpc(
        self,
        session_id: str,
        obj: str,
        fn: str,
        args: Mapping[str, Any] | None = None,
    ) -> Any:
        self._next_id += 1
        payload = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": self._next_id,
                "method": "call",
                "params": [session_id, obj, fn, dict(args or {})],
            }
        ).encode("utf-8")
        host_header = f"{self.host}:{self.port}".encode("ascii")
        request = (
            b"POST /ubus HTTP/1.1\r\n"
            b"Host: " + host_header + b"\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(payload)).encode("ascii") + b"\r\n"
            b"Connection: close\r\n"
            b"\r\n" + payload
        )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        # The certificate is self-signed and pinned by its SPKI instead:
        # the pin is the check, and it happens before anything is sent.
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        sent = False
        try:
            with socket.create_connection(
                (self.host, self.port), timeout=self.timeout_s
            ) as plain:
                with context.wrap_socket(plain, server_hostname=self.host) as tls:
                    peer = tls.getpeercert(binary_form=True)
                    if not peer:
                        raise RpcdTransportError(
                            "the router sent no certificate", sent=False
                        )
                    if not hmac.compare_digest(spki_pin(peer), self.pin):
                        raise RpcdPinMismatch(
                            "the certificate's SPKI is not the pinned one: "
                            "nothing was sent",
                            sent=False,
                        )
                    sent = True
                    try:
                        tls.sendall(request)
                    except OSError as exc:
                        raise RpcdTransportError(
                            f"the request could not be sent: {exc}", sent=True
                        ) from None
                    return self._read_answer(tls, obj, fn)
        except RpcdError:
            raise
        except OSError as exc:
            raise RpcdTransportError(
                f"the router could not be reached: {exc}", sent=sent
            ) from None

    def _read_answer(self, tls: ssl.SSLSocket, obj: str, fn: str) -> Any:
        response = http.client.HTTPResponse(tls)
        try:
            response.begin()
            # the router answered over HTTPS: this transport ran, and
            # the lab runner is told about it (one line, the method)
            note_rpcd_call(obj, fn)
            if response.status != 200:
                # A redirect is not followed: a 3xx is a refused answer.
                raise RpcdTransportError(
                    f"the router answered with HTTP {response.status}", sent=True
                )
            body = response.read(MAX_BODY + 1)
        except RpcdError:
            raise
        except (http.client.HTTPException, OSError, ssl.SSLError):
            # A body that stops in the middle, a broken status line, a
            # closed socket: the request went out, so the change may
            # have been applied and the answer has to be resolved.  The
            # router's own text never goes into the message.
            raise RpcdTransportError(
                "the router's answer could not be read", sent=True
            ) from None
        if len(body) > MAX_BODY:
            raise RpcdTransportError(
                f"the router's answer is larger than {MAX_BODY} bytes", sent=True
            )
        try:
            answer = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise RpcdTransportError(
                "the router's answer is not JSON", sent=True
            ) from None
        return self._unwrap(answer)

    def _unwrap(self, answer: Any) -> Any:
        if not isinstance(answer, Mapping):
            raise RpcdTransportError(
                "the router's answer is not a JSON-RPC object", sent=True
            )
        error = answer.get("error")
        if isinstance(error, Mapping):
            code = error.get("code")
            if isinstance(code, bool) or not isinstance(code, int):
                # The router's own text never goes into an error: only a
                # number is a code, and only a number is ever shown.
                raise RpcdTransportError(
                    "the router answered with a malformed error", sent=True
                )
            if code == -32002:
                raise RpcdAccessDenied(
                    "the router refused the session: access denied, or the "
                    "session expired"
                )
            raise RpcdTransportError(
                f"the router answered with an error: {code_name(code)}",
                sent=True,
            )
        result = answer.get("result")
        if not isinstance(result, (list, tuple)) or not result:
            raise RpcdTransportError(
                "the router's answer carries no result", sent=True
            )
        code = result[0]
        if isinstance(code, bool) or not isinstance(code, int):
            raise RpcdTransportError(
                "the router's result code is not a number", sent=True
            )
        if code != 0:
            raise RpcdCallFailed(code)
        if len(result) == 1:
            return {}
        return result[1]
