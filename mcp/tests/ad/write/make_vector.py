"""Generate the AD write request test vector (SPEC-1.4-REQUEST section 4).

The vector is generated once, by this script, and the two files it writes
are committed: the request itself and the expected canonical bytes, digest
and token.  The Windows and Samba write helpers reproduce the same
bytes with their own implementation, so the vector may never drift.

Run it with the MCP venv:

    mcp/.venv/bin/python mcp/tests/ad/write/make_vector.py

The script writes into ``mcp/tests/ad/fixtures/``.
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path


_MCP_ROOT = Path(__file__).resolve().parents[3]
if str(_MCP_ROOT) not in sys.path:
    sys.path.insert(0, str(_MCP_ROOT))

from newton_mcp.ad.write import request  # noqa: E402


#: The key of the vector: 32 bytes of 0x11 (section 4).
K_HEX = "11" * 32

#: The device of the vector: the domain the request names.
DEVICE = "lab-win"

#: The transaction id of the vector.
TXID = "0123456789abcdef0123456789abcdef"

#: The approval window of the vector.
NBF = 1800000000
EXP = 1800000600

#: The request of the vector: a uac-clear of DONT_REQ_PREAUTH.
REQUEST: dict[str, object] = {
    "v": 1,
    "mode": "apply",
    "device": DEVICE,
    "txid": TXID,
    "verb": "uac-clear",
    "target": {
        "guid": "6f9619ff-8b86-d011-b42d-00c04fc964ff",
        "sid": "S-1-5-21-1-2-3-1105",
        "sam": "seed-asrep",
        "bit": 4194304,
    },
    "before": {"uac": 4260352},
    "after": {"uac": 66048},
    "window": 600,
    "risk": "MED",
    "nbf": NBF,
    "exp": EXP,
}


def fixture_dir() -> Path:
    """The directory the two fixture files live in."""
    return _MCP_ROOT / "tests" / "ad" / "fixtures"


def build_request() -> dict[str, object]:
    """The request of the vector, with its token."""
    payload = json.loads(json.dumps(REQUEST))
    payload["token"] = request.token(
        K_HEX, request.digest(payload), NBF, EXP
    )
    return payload


def build_expected(payload: dict[str, object]) -> dict[str, str]:
    """The expected canonical bytes, digest and token of the vector."""
    canonical = request.canonical_bytes(payload)
    return {
        "canonical_b64": base64.b64encode(canonical).decode("ascii"),
        "digest": request.digest(payload),
        "token": str(payload["token"]),
    }


def render(value: object) -> bytes:
    """The bytes of one fixture file."""
    return (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    ).encode("utf-8")


def write_fixtures(directory: Path | None = None) -> tuple[Path, Path]:
    """Write the two fixture files and return their paths."""
    target = fixture_dir() if directory is None else directory
    target.mkdir(parents=True, exist_ok=True)
    payload = build_request()
    request_path = target / "write-request-v1.json"
    expected_path = target / "write-request-v1.expected.json"
    request_path.write_bytes(render(payload))
    expected_path.write_bytes(render(build_expected(payload)))
    return request_path, expected_path


def main() -> int:
    request_path, expected_path = write_fixtures()
    print(f"wrote {request_path}")
    print(f"wrote {expected_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
