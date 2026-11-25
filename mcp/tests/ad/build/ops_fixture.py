"""The ops section of the plans of the build tests (the maintainer's decision R1,
2026-11-15): stage 8's newton-ops public key and the sha256 of the 1.4
write helper the stage installs.

The key is synthetic (an ed25519 blob of the bytes 0 to 31).  The sha256 is
the one of the package's ``write.ps1``, so a plan of these tests is a plan
whose stage 8 the installed Newton can serve.
"""

from __future__ import annotations

import base64
import hashlib

from newton_mcp.ad import setupgen_write

#: The newton-ops public key line of the tests.
OPS_PUBLIC_KEY = "ssh-ed25519 " + base64.b64encode(
    b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + bytes(range(32))
).decode("ascii")

#: The newton-audit public key line of the tests (the maintainer's decision on open
#: point 34, 2026-11-16): the bytes 64 to 95.
AUDIT_PUBLIC_KEY = "ssh-ed25519 " + base64.b64encode(
    b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + bytes(range(64, 96))
).decode("ascii")

#: The sha256 of the package's 1.4 write helper.
WRITE_HELPER_SHA256 = hashlib.sha256(setupgen_write.WRITE_HELPER_PATH.read_bytes()).hexdigest()

#: The ops section.
OPS: dict[str, str] = {
    "audit_public_key": AUDIT_PUBLIC_KEY,
    "public_key": OPS_PUBLIC_KEY,
    "write_helper_sha256": WRITE_HELPER_SHA256,
}
