from __future__ import annotations

import os

import pytest

from newton_mcp import redact


SECRET = "ObviousFakeMultilineSecret987"
KEY = b"r" * 32


def test_multiline_dotted_secret_is_one_value_and_following_line_survives():
    text = f"wireless.x.key='alpha\n{SECRET}'\nwireless.x.ssid='safe'"
    out = redact.redact_text(text, KEY)
    assert SECRET not in out
    assert out.count("<redacted:") == 1
    assert "wireless.x.ssid='safe'" in out


def test_multiline_file_secret_is_one_value_and_following_line_survives():
    text = f"config wifi-iface 'x'\n\toption key 'alpha\n{SECRET}'\n\toption ssid 'safe'"
    out = redact.redact_text(text, KEY)
    assert SECRET not in out
    assert out.count("<redacted:") == 1
    assert "option ssid 'safe'" in out


def test_closed_file_quote_with_comment_does_not_swallow_next_line():
    text = "\toption key 'alpha' # note\n\toption ssid 'safe'"
    out = redact.redact_text(text, KEY)
    assert "# note" not in out
    assert "option ssid 'safe'" in out


@pytest.mark.parametrize("hash_id", ["2", "2x", "3", "7", "gy", "apr1", "md5", "sha1", "sha256", "sha512"])
def test_additional_shadow_hash_ids_are_redacted(hash_id):
    value = f"${hash_id}$salt$ObviousFakeHash987"
    out = redact.redact_text(f"root:{value}:0:0:99999:7:::", KEY)
    assert value not in out
    assert "root:<redacted:" in out


def test_legacy_des_shadow_field_and_negative_lines():
    secret = "Ab12Cd34Ef56g"
    line = f"root:{secret}:0:0:99999:7:::"
    assert secret not in redact.redact_text(line, KEY)
    for safe in (
        "daemon:*:0:0:99999:7:::", "root:!:0:0:99999:7:::",
        "root:x:0:0:root:/root:/bin/ash",
    ):
        assert redact.redact_text(safe, KEY) == safe


@pytest.mark.parametrize(
    "label",
    ["PGP PRIVATE KEY BLOCK", "OpenVPN Static key V1"],
)
@pytest.mark.parametrize("terminated", [True, False])
def test_additional_private_key_blocks_redact_to_end(label, terminated):
    text = f"-----BEGIN {label}-----\n{SECRET}"
    if terminated:
        text += f"\n-----END {label}-----"
    out = redact.redact_text(text, KEY)
    assert SECRET not in out
    assert out.startswith("<redacted:")


@pytest.mark.parametrize("length", [0, 1, 31, 33, 64])
def test_existing_key_must_be_exactly_32_bytes(tmp_path, length):
    path = tmp_path / "redact.key"
    path.write_bytes(b"x" * length)
    os.chmod(path, 0o600)
    with pytest.raises(RuntimeError, match=r"exactly 32 bytes.*redact\.key"):
        redact._load_or_create_key(tmp_path)


def test_atomic_key_creation_returns_winners_key_on_link_race(tmp_path, monkeypatch):
    winner = b"w" * 32

    def losing_link(_source, destination):
        destination = os.fspath(destination)
        with open(destination, "xb") as stream:
            stream.write(winner)
        os.chmod(destination, 0o600)
        raise FileExistsError(destination)

    monkeypatch.setattr(redact.os, "link", losing_link)
    assert redact._load_or_create_key(tmp_path) == winner
    assert (tmp_path / "redact.key").read_bytes() == winner
    assert not list(tmp_path.glob(".redact.key.*"))


def test_created_key_is_32_bytes_mode_0600(tmp_path):
    key = redact._load_or_create_key(tmp_path)
    assert len(key) == 32
    assert (tmp_path / "redact.key").stat().st_mode & 0o777 == 0o600


def test_new_multiline_and_block_forms_are_idempotent():
    text = f"wireless.x.key='a\n{SECRET}'\n-----BEGIN PGP PRIVATE KEY BLOCK-----\n{SECRET}"
    once = redact.redact_text(text, KEY)
    assert redact.redact_text(once, KEY) == once
