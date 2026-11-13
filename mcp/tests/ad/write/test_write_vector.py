"""The AD write request test vector (SPEC-1.4-REQUEST section 4).

The vector is generated once, by ``make_vector.py``, and the two files it
writes are committed.  Two tests hold it in place: one compares the files
on disk with the output of the script byte for byte, and one spells the
canonical text out as a literal, so a change of the canonical rules can
never slip through unnoticed.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import make_vector

from newton_mcp.ad.write import request


#: The canonical text of the vector, spelled out.
CANONICAL = (
    "newton-ad-request-v1\n"
    "device=lab-win\n"
    "txid=0123456789abcdef0123456789abcdef\n"
    "verb=uac-clear\n"
    "target=bit=4194304,guid=6f9619ff-8b86-d011-b42d-00c04fc964ff,"
    "sam=seed-asrep,sid=S-1-5-21-1-2-3-1105\n"
    "before=uac=4260352\n"
    "after=uac=66048\n"
    "window=600\n"
    "risk=MED\n"
    "secret=-\n"
    "helper=1\n"
)


def test_the_fixtures_match_the_script_byte_for_byte() -> None:
    """The committed files are the output of the script."""
    directory = make_vector.fixture_dir()
    payload = make_vector.build_request()

    assert (directory / "write-request-v1.json").read_bytes() == make_vector.render(
        payload
    )
    assert (
        directory / "write-request-v1.expected.json"
    ).read_bytes() == make_vector.render(make_vector.build_expected(payload))


def test_the_canonical_text_is_the_literal_one() -> None:
    """The canonical bytes are the ten lines, spelled out."""
    payload = json.loads(
        (make_vector.fixture_dir() / "write-request-v1.json").read_text(
            encoding="utf-8"
        )
    )

    assert request.canonical_bytes(payload).decode("ascii") == CANONICAL


def test_the_expected_file_holds_the_canonical_bytes_the_digest_and_the_token() -> None:
    """The expected file agrees with the request file."""
    directory = make_vector.fixture_dir()
    payload = json.loads(
        (directory / "write-request-v1.json").read_text(encoding="utf-8")
    )
    expected = json.loads(
        (directory / "write-request-v1.expected.json").read_text(encoding="utf-8")
    )

    canonical = request.canonical_bytes(payload)
    assert base64.b64decode(expected["canonical_b64"]) == canonical
    assert expected["digest"] == request.digest(payload)
    assert expected["token"] == payload["token"]


def test_the_vector_request_is_a_request_the_contract_accepts() -> None:
    """The request of the vector parses."""
    raw = (make_vector.fixture_dir() / "write-request-v1.json").read_bytes()

    parsed = request.parse_request(raw)

    assert parsed["verb"] == "uac-clear"
    assert parsed["device"] == "lab-win"
    assert parsed["risk"] == "MED"


def test_the_vector_token_is_the_router_token_over_the_vector_digest() -> None:
    """The token of the vector is minted over the digest of the vector."""
    from newton_mcp import approve

    directory = make_vector.fixture_dir()
    payload = json.loads(
        (directory / "write-request-v1.json").read_text(encoding="utf-8")
    )
    expected = json.loads(
        (directory / "write-request-v1.expected.json").read_text(encoding="utf-8")
    )

    assert payload["token"] == approve.approval_token(
        make_vector.K_HEX, expected["digest"], make_vector.NBF, make_vector.EXP
    )


def test_the_script_writes_the_same_bytes_into_a_fresh_directory(tmp_path: Path) -> None:
    """The script writes the committed bytes, not another shape."""
    request_path, expected_path = make_vector.write_fixtures(tmp_path)

    assert request_path.read_bytes() == (
        make_vector.fixture_dir() / "write-request-v1.json"
    ).read_bytes()
    assert expected_path.read_bytes() == (
        make_vector.fixture_dir() / "write-request-v1.expected.json"
    ).read_bytes()
