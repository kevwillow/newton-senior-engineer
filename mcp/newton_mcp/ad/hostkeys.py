"""The host keys of a domain controller, fetched with ``ssh-keyscan``.

One scan per controller.  For every key the tool prints its SHA256
fingerprint (the way ``ssh-keygen -lf`` prints it) and the ready
``known_hosts`` line.  Nothing is written: the owner decides what to do
with the lines, and nothing else runs.

A scan travels over the network, so it can be spoofed.  A fingerprint is
only worth something when the owner compares it with the one the
controller shows at its console; that is what the caller prints.

What comes back is untrusted:

- only these key types are kept: ``ssh-ed25519``, ``ecdsa-sha2-nistp256``,
  ``ecdsa-sha2-nistp384``, ``ecdsa-sha2-nistp521`` and ``ssh-rsa``;
- the blob must be valid base64, and it must carry the key type the line
  names;
- the lines that start with a hash are the comments ``ssh-keyscan``
  writes, and are ignored;
- the host name that is printed is the one that was asked for, never the
  one the answer carries.

``MAX_KEYS`` and ``MAX_BLOB`` are caps on what is kept and printed: at
most ``MAX_KEYS`` keys of one host, and no blob longer than
``MAX_BLOB``.  They say nothing about how much the program reads: there
is no size cap on what is read, the whole answer of a scan is read into
memory before it is parsed.  A timeout bounds time, not bytes.

When a host has more valid keys than the cap allows, the scan says the
list was cut: the owner has to know that the keys shown are not all of
them.

``ssh-keyscan`` is run with an argument list, never through a shell, and
with a timeout.  The tests give the tool a fake runner, so no test
touches the network.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import subprocess
from dataclasses import dataclass, field
from typing import Protocol

# The key types that are kept.
KEY_TYPES = (
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "ssh-rsa",
)

# What ssh-keyscan is asked for, and how.
SCAN_TYPES = "ed25519,ecdsa,rsa"
SCAN_TIMEOUT = "5"
SCAN_PORT = "22"

# The timeout of the program itself, in seconds: a ceiling on the whole
# scan of one host.  ssh-keyscan's own 5 s (-T) is per connection attempt
# or read, so an endpoint that answers slowly can take longer than 5 s;
# 30 s is six times that, a margin for such an endpoint, not a count of rounds:
# the key types are asked at once (on OpenSSH 9.6, against a silent
# endpoint, -T 3 takes 3.01 s with one key type and 3.01 s with three:
# the connections open at the same moment).
PROGRAM_TIMEOUT = 30.0

# The most keys one host may contribute, and the longest blob that is
# kept: both bound what is printed, not what is read.
MAX_KEYS = 8
MAX_BLOB = 8192


class Runner(Protocol):
    """What the tool needs of the program it runs."""

    def __call__(self, argv: list[str], timeout: float) -> str: ...


@dataclass(frozen=True)
class HostKey:
    """One host key: its type, its blob and its fingerprint."""

    keytype: str
    blob: str
    fingerprint: str


@dataclass(frozen=True)
class Scan:
    """What one scan of one host gave.

    ``keys`` are the keys that are kept.  ``cut`` says that more valid
    keys were found than the cap allows, so the keys are not all of
    them.  ``note`` is the reason when there are no keys at all.
    """

    keys: list[HostKey] = field(default_factory=list)
    cut: bool = False
    note: str = ""


def run_program(argv: list[str], timeout: float) -> str:
    """Run the program with an argument list and return what it printed.

    There is no shell: the arguments go to the program as they are.  A
    program that fails is an error, never a silent empty answer.  The
    whole output is captured in memory: a timeout bounds time, not
    bytes, so there is no size cap on what is read.
    """
    result = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        raise OSError(f"the program failed with exit code {result.returncode}")
    return result.stdout


def _blob_type(raw: bytes) -> str:
    """The key type a blob carries, or the empty string."""
    if len(raw) < 4:
        return ""
    length = int.from_bytes(raw[:4], "big")
    if length > len(raw) - 4 or length > 64:
        return ""
    try:
        return raw[4 : 4 + length].decode("ascii")
    except UnicodeDecodeError:
        return ""


def fingerprint(raw: bytes) -> str:
    """The SHA256 fingerprint of a key blob, the way ``ssh-keygen -lf`` prints it."""
    digest = hashlib.sha256(raw).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def parse_keys(output: str) -> tuple[list[HostKey], bool]:
    """The host keys of one scan, the ones that are kept, and whether the list was cut.

    A key type that is not kept, a blob that is not valid base64 and a
    blob that does not carry the type the line names are all dropped.
    At most ``MAX_KEYS`` keys are kept and a blob longer than
    ``MAX_BLOB`` is dropped: these two caps bound what is kept and
    printed, not what is read.  When a further valid key is found past
    the cap, the list is cut and the second value says so: the owner
    has to know that the keys shown are not all of them.
    """
    keys: list[HostKey] = []
    seen: set[tuple[str, str]] = set()
    cut = False
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        keytype, blob = parts[1], parts[2]
        if keytype not in KEY_TYPES or len(blob) > MAX_BLOB:
            continue
        try:
            raw = base64.b64decode(blob, validate=True)
        except (binascii.Error, ValueError):
            continue
        if _blob_type(raw) != keytype:
            continue
        if (keytype, blob) in seen:
            continue
        if len(keys) >= MAX_KEYS:
            cut = True
            break
        seen.add((keytype, blob))
        keys.append(HostKey(keytype=keytype, blob=blob, fingerprint=fingerprint(raw)))
    return keys, cut


def scan_host(host: str, runner: Runner) -> Scan:
    """The host keys of one controller, and the reason when there are none.

    The scan is one ``ssh-keyscan`` with an argument list and a timeout.
    A failure never stops the run: the caller prints a plain line and
    keeps the placeholder.
    """
    argv = [
        "ssh-keyscan",
        "-T",
        SCAN_TIMEOUT,
        "-t",
        SCAN_TYPES,
        "-p",
        SCAN_PORT,
        host,
    ]
    try:
        output = runner(argv, PROGRAM_TIMEOUT)
    except subprocess.TimeoutExpired:
        return Scan(note="the scan did not answer in time")
    except OSError:
        return Scan(note="the scan failed")
    keys, cut = parse_keys(output)
    if not keys:
        return Scan(note="the scan returned no host key")
    return Scan(keys=keys, cut=cut)
