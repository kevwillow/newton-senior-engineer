"""Shared helpers for the rpcd tests.

The tests never contact a router: they talk to a TLS server thread
on 127.0.0.1 that answers like the router's own /ubus, with a
certificate generated in the test.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import http.server
import json
import socket
import ssl
import tempfile
import threading
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def self_signed() -> tuple[bytes, bytes, bytes]:
    """A self-signed EC P-256 certificate, as (cert_pem, key_pem, cert_der)."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "OpenWrt")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    return (
        cert.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        cert.public_bytes(serialization.Encoding.DER),
    )


def pin_of(cert_pem: bytes) -> str:
    """The SPKI sha256 (base64) of a PEM certificate."""
    cert = x509.load_pem_x509_certificate(cert_pem)
    spki = cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(hashlib.sha256(spki).digest()).decode("ascii")


def write_temp(data: bytes, suffix: str) -> str:
    handle = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)
    handle.write(data)
    handle.close()
    return handle.name


def ok(result) -> tuple[int, bytes]:
    """A JSON-RPC answer of the shape the router sends."""
    return 200, json.dumps({"jsonrpc": "2.0", "id": 1, "result": result}).encode()


class Router:
    """A local TLS server that answers like the router's /ubus."""

    def __init__(self, cert_pem: bytes, key_pem: bytes, reply) -> None:
        self.received: list[bytes] = []
        self._reply = reply
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self) -> None:  # noqa: N802 (http.server's name)
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length)
                outer.received.append(body)
                status, payload = outer._reply(body)
                raw = payload if isinstance(payload, bytes) else payload.encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, *args) -> None:
                pass

        self._server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._paths = (write_temp(cert_pem, ".pem"), write_temp(key_pem, ".key"))
        context.load_cert_chain(certfile=self._paths[0], keyfile=self._paths[1])
        self._server.socket = context.wrap_socket(self._server.socket, server_side=True)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def __enter__(self) -> "Router":
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)
        for path in self._paths:
            Path(path).unlink(missing_ok=True)


class Raw:
    """A raw HTTP answer, sent byte for byte.

    The scripted router sends it instead of a JSON-RPC answer, so a
    test can plant a malformed status line or a broken body.
    """

    def __init__(self, payload: bytes) -> None:
        self.payload = payload


class ScriptedRouter:
    """A TLS server that answers ubus calls from a script.

    The handler is called with ``(obj, fn, args)`` and answers the
    ubus result (the list the router sends, ``[0, data]``).  A call
    named in ``truncate`` gets an answer that stops in the middle: the
    client must treat that as a lost answer, not as a refusal.
    """

    def __init__(
        self,
        cert_pem: bytes,
        key_pem: bytes,
        handler,
        truncate: tuple[str, ...] = (),
    ) -> None:
        self.received: list[dict] = []
        self._handler = handler
        self._truncate = set(truncate)
        self._context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._paths = (write_temp(cert_pem, ".pem"), write_temp(key_pem, ".key"))
        self._context.load_cert_chain(certfile=self._paths[0], keyfile=self._paths[1])
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind(("127.0.0.1", 0))
        self._server.listen(8)
        self.port = self._server.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self) -> "ScriptedRouter":
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._server.close()
        self._thread.join(timeout=5)
        for path in self._paths:
            Path(path).unlink(missing_ok=True)

    # -- the wire ------------------------------------------------------------

    def _serve(self) -> None:
        while True:
            try:
                raw, _ = self._server.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(raw,), daemon=True).start()

    def _handle(self, raw: socket.socket) -> None:
        try:
            with self._context.wrap_socket(raw, server_side=True) as tls:
                request = self._read_request(tls)
                if request is None:
                    return
                obj, fn, args = request
                result = self._handler(obj, fn, args)
                if isinstance(result, Raw):
                    tls.sendall(result.payload)
                elif f"{obj}.{fn}" in self._truncate:
                    self._send_truncated(tls)
                else:
                    self._send_json(tls, result)
                try:
                    tls.unwrap()
                except (OSError, ssl.SSLError):
                    pass
        except (OSError, ssl.SSLError, ValueError):
            return

    def _read_request(self, tls: ssl.SSLSocket):
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = tls.recv(4096)
            if not chunk:
                return None
            data += chunk
        head, _, rest = data.partition(b"\r\n\r\n")
        length = 0
        for line in head.split(b"\r\n")[1:]:
            name, _, value = line.partition(b":")
            if name.strip().lower() == b"content-length":
                length = int(value.strip())
        while len(rest) < length:
            chunk = tls.recv(4096)
            if not chunk:
                break
            rest += chunk
        request = json.loads(rest[:length].decode("utf-8"))
        self.received.append(request)
        params = request.get("params") or []
        return params[1], params[2], params[3]

    def _send_json(self, tls: ssl.SSLSocket, payload) -> None:
        answer = {"jsonrpc": "2.0", "id": 1, "result": payload}
        body = json.dumps(answer).encode("utf-8")
        tls.sendall(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
            b"\r\n" + body
        )

    def _send_truncated(self, tls: ssl.SSLSocket) -> None:
        """A chunked body that stops before its last chunk."""
        body = b'{"jsonrpc": "2.0", "id": 1, "result": [0, {}]}'
        tls.sendall(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"\r\n"
            + f"{len(body):x}\r\n".encode("ascii")
            + body
            + b"\r\n"
        )
