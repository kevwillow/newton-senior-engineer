"""the password file for password auth holds a credential.

Two checks guard it, and both are now the same shape as the key_file
rule the inventory already enforces: the file must be a regular file
(not a symlink), must have mode exactly 0600 and must be owned by the
user running the MCP server.

``load_inventory`` (server.py) does the lstat / owner / mode check;
``build_argv`` (adapters/ssh_cli.py) re-checks the mode, because the
argv builder is the last gate before the path reaches an askpass helper.

All values here are synthetic; the password file never holds a real
credential.
"""

from __future__ import annotations

import dataclasses
import stat
from pathlib import Path

import pytest

import newton_mcp.server as server
from newton_mcp.adapters.ssh_cli import RunnerRefused, build_argv


@dataclasses.dataclass(frozen=True)
class _Target:
    """Concrete SshTarget for build_argv tests (Protocol can't instantiate)."""

    name: str
    platform: str
    host: str
    user: str
    auth: str
    port: int
    password_file: Path | None
    proxy_command: str | None
    key_file: Path | None
    known_hosts: Path | None


def _known_hosts(tmp_path: Path) -> Path:
    path = tmp_path / "known-hosts"
    path.write_text("key ssh-ed25519 synthetic\n", encoding="utf-8")
    return path


def _password_target(tmp_path: Path, password_file: Path) -> _Target:
    return _Target(
        name="lab-r1",
        platform="junos",
        host="router.test",
        user="admin",
        auth="password",
        port=22,
        password_file=password_file,
        proxy_command=None,
        key_file=None,
        known_hosts=_known_hosts(tmp_path),
    )


def _password_file(tmp_path: Path, mode: int = 0o600) -> Path:
    path = tmp_path / "password"
    path.write_text("synthetic-password\n", encoding="utf-8")
    path.chmod(mode)
    return path


def _inventory(tmp_path, monkeypatch, password_file) -> Path:
    path = tmp_path / "devices.toml"
    path.write_text(
        '[devices.quasar]\nplatform = "openwrt"\nhost = "192.0.2.1"\nuser = "root"\n'
        f'auth = "password"\npassword_file = "{password_file}"\n'
    )
    path.chmod(0o644)
    monkeypatch.setenv("NEWTON_INVENTORY", str(path))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    return path


# ---- load_inventory (server.py) ---------------------------------------------


def test_mode_0600_password_file_is_accepted(tmp_path, monkeypatch):
    password = _password_file(tmp_path, 0o600)
    _inventory(tmp_path, monkeypatch, password)
    assert server.load_inventory()["quasar"].password_file == password


def test_mode_0640_password_file_is_refused(tmp_path, monkeypatch):
    password = _password_file(tmp_path, 0o640)
    _inventory(tmp_path, monkeypatch, password)
    with pytest.raises(
        server.NewtonError,
        match=r"device quasar: password file must have mode 0600",
    ):
        server.load_inventory()


def test_symlink_password_file_is_refused(tmp_path, monkeypatch):
    real = _password_file(tmp_path, 0o600)
    link = tmp_path / "password-link"
    link.symlink_to(real)
    _inventory(tmp_path, monkeypatch, link)
    with pytest.raises(
        server.NewtonError,
        match=r"device quasar: password file must be a regular file, not a symlink",
    ):
        server.load_inventory()


def test_directory_password_file_is_refused(tmp_path, monkeypatch):
    directory = tmp_path / "password-dir"
    directory.mkdir()
    _inventory(tmp_path, monkeypatch, directory)
    with pytest.raises(
        server.NewtonError,
        match=r"device quasar: password file must be a regular file, not a symlink",
    ):
        server.load_inventory()


def test_password_file_owned_by_another_user_is_refused(tmp_path, monkeypatch):
    password = _password_file(tmp_path, 0o600)
    _inventory(tmp_path, monkeypatch, password)
    monkeypatch.setattr(server.os, "geteuid", lambda: password.stat().st_uid + 1)
    with pytest.raises(
        server.NewtonError,
        match=r"device quasar: password file must be owned by the server user",
    ):
        server.load_inventory()


def test_password_file_refusal_names_the_device_not_the_content(
    tmp_path, monkeypatch
):
    password = tmp_path / "password"
    password.write_text("synthetic-password-value\n", encoding="utf-8")
    password.chmod(0o644)
    _inventory(tmp_path, monkeypatch, password)
    with pytest.raises(server.NewtonError) as exc:
        server.load_inventory()
    message = str(exc.value)
    assert "quasar" in message
    assert "synthetic-password-value" not in message


# ---- build_argv (adapters/ssh_cli.py) ---------------------------------------


def test_build_argv_accepts_mode_0600_password_file(tmp_path):
    password = _password_file(tmp_path, 0o600)
    argv = build_argv(_password_target(tmp_path, password), "show version")
    assert argv[-1] == "show version"


def test_build_argv_refuses_mode_0644_password_file(tmp_path):
    password = _password_file(tmp_path, 0o644)
    with pytest.raises(RunnerRefused) as caught:
        build_argv(_password_target(tmp_path, password), "show version")
    assert "password_file must have mode 0600" in str(caught.value)


def test_build_argv_refuses_a_password_file_owned_by_another_user(tmp_path, monkeypatch):
    password = _password_file(tmp_path, 0o600)
    monkeypatch.setattr(
        "newton_mcp.adapters.ssh_cli.os.geteuid", lambda: password.stat().st_uid + 1
    )
    with pytest.raises(RunnerRefused) as caught:
        build_argv(_password_target(tmp_path, password), "show version")
    assert "password_file must be owned by the server user" in str(caught.value)


def test_build_argv_refuses_a_symlinked_password_file(tmp_path):
    real = _password_file(tmp_path, 0o600)
    link = tmp_path / "password-link"
    link.symlink_to(real)
    with pytest.raises(RunnerRefused) as caught:
        build_argv(_password_target(tmp_path, link), "show version")
    assert "password_file" in str(caught.value)


def test_build_argv_still_refuses_a_missing_password_file(tmp_path):
    with pytest.raises(RunnerRefused) as caught:
        build_argv(
            _password_target(tmp_path, tmp_path / "no-such-password"),
            "show version",
        )
    assert "password_file must be an existing regular file" in str(caught.value)


def test_the_mode_is_read_from_the_file_not_from_the_umask(tmp_path):
    """The check is the file's own mode, not the process umask."""
    password = _password_file(tmp_path, 0o600)
    assert stat.S_IMODE(password.stat().st_mode) == 0o600
    target = _password_target(tmp_path, password)
    assert build_argv(target, "show version")
