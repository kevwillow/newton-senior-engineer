"""MCP-only filesystem rules for key_file (setup checks only the syntax):
the file must exist, be a regular file (not a symlink), have mode exactly
0600 and be owned by the user running the MCP server (os.geteuid())."""

import pytest

import newton_mcp.server as server


def inventory_with(tmp_path, key_file):
    path = tmp_path / "devices.toml"
    path.write_text(
        '[devices.quasar]\nplatform="openwrt"\nhost="192.0.2.1"\nuser="root"\n'
        f'key_file="{key_file}"\n'
    )
    return path


def load(tmp_path, monkeypatch, key_file):
    monkeypatch.setenv("NEWTON_INVENTORY", str(inventory_with(tmp_path, key_file)))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    return server.load_inventory()


def test_mode_0600_key_file_is_accepted(tmp_path, monkeypatch):
    key = tmp_path / "newton-key"
    key.write_text("FAKE-KEY-FOR-TESTS\n")
    key.chmod(0o600)
    assert load(tmp_path, monkeypatch, key)["quasar"].key_file == key


def test_mode_0644_key_file_is_refused(tmp_path, monkeypatch):
    key = tmp_path / "newton-key"
    key.write_text("FAKE-KEY-FOR-TESTS\n")
    key.chmod(0o644)
    with pytest.raises(server.NewtonError, match=r"device quasar: key_file .*mode 0600"):
        load(tmp_path, monkeypatch, key)


def test_symlink_key_file_is_refused(tmp_path, monkeypatch):
    real = tmp_path / "real-key"
    real.write_text("FAKE-KEY-FOR-TESTS\n")
    real.chmod(0o600)
    key = tmp_path / "newton-key"
    key.symlink_to(real)
    with pytest.raises(server.NewtonError, match=r"device quasar: key_file .*not a symlink"):
        load(tmp_path, monkeypatch, key)


def test_key_file_owned_by_another_user_is_refused(tmp_path, monkeypatch):
    key = tmp_path / "newton-key"
    key.write_text("FAKE-KEY-FOR-TESTS\n")
    key.chmod(0o600)
    monkeypatch.setattr(server.os, "geteuid", lambda: key.stat().st_uid + 1)
    with pytest.raises(server.NewtonError, match=r"device quasar: key_file .*owned by"):
        load(tmp_path, monkeypatch, key)


def test_missing_key_file_is_refused(tmp_path, monkeypatch):
    with pytest.raises(server.NewtonError, match=r"device quasar: key_file .*regular file"):
        load(tmp_path, monkeypatch, tmp_path / "gone-key")


def test_key_file_error_names_the_device_and_rule_not_the_content(tmp_path, monkeypatch):
    key = tmp_path / "newton-key"
    key.write_text("made-up-key-material\n")
    key.chmod(0o644)
    monkeypatch.setenv("NEWTON_INVENTORY", str(inventory_with(tmp_path, key)))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    with pytest.raises(server.NewtonError) as exc:
        server.load_inventory()
    assert "made-up-key-material" not in str(exc.value)
    assert "quasar" in str(exc.value)
