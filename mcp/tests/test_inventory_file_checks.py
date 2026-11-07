"""MCP-only filesystem rules for the inventory file itself
(devices.toml under NEWTON_INVENTORY or ~/.config/newton/devices.toml):
it must exist, be a regular file (not a symlink), not be group- or
world-writable, and be owned by the user running the MCP server
(os.geteuid()).  The same rule applies to the loader in server.py and
the loader in scans.py; both call a shared helper in
newton_mcp.inventory_file so the check stays in one place.

The original "inventory file not found" message is kept for the missing
path case; this module only adds refusals for the bad-mode/bad-owner
cases the key_file checks already had."""

import pytest

import newton_mcp.inventory_file as inventory_file
import newton_mcp.scans as scans
import newton_mcp.server as server


SAMPLE_DEVICES = (
    '[devices.quasar]\nplatform="openwrt"\nhost="192.0.2.1"\nuser="root"\n'
)
SAMPLE_VANTAGES = (
    '[devices.quasar]\nplatform="openwrt"\nhost="192.0.2.1"\nuser="root"\n'
    'wan_zones=["wan"]\n\n'
    '[vantages.inside-a]\nhost="scan.example.invalid"\nuser="newton"\n'
    'key_file="/tmp/inside-a.key"\nknown_hosts="/tmp/inside-a.hosts"\n'
    'role="inside"\ndevices=["quasar"]\n'
)


def _write_inventory(tmp_path, *, content, mode=0o644):
    path = tmp_path / "devices.toml"
    path.write_text(content)
    if mode is not None:
        path.chmod(mode)
    return path


def _vantage_inputs(tmp_path, content):
    """Replace the placeholder /tmp paths in a vantages inventory with
    real files in tmp_path so the per-vantage key_file / known_hosts
    checks pass; return the rewritten content."""
    key = tmp_path / "inside-a.key"
    key.write_text("synthetic-key")
    key.chmod(0o600)
    hosts = tmp_path / "inside-a.hosts"
    hosts.write_text("synthetic host key\n")
    hosts.chmod(0o644)
    return (
        content.replace("/tmp/inside-a.key", str(key))
        .replace("/tmp/inside-a.hosts", str(hosts))
    )


def _set_inventory(tmp_path, monkeypatch, path):
    monkeypatch.setenv("NEWTON_INVENTORY", str(path))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))


# ---- server.py: load_inventory ----------------------------------------------


def test_server_accepts_inventory_mode_0600(tmp_path, monkeypatch):
    path = _write_inventory(tmp_path, content=SAMPLE_DEVICES, mode=0o600)
    _set_inventory(tmp_path, monkeypatch, path)
    assert "quasar" in server.load_inventory()


def test_server_accepts_inventory_mode_0644(tmp_path, monkeypatch):
    path = _write_inventory(tmp_path, content=SAMPLE_DEVICES, mode=0o644)
    _set_inventory(tmp_path, monkeypatch, path)
    assert "quasar" in server.load_inventory()


@pytest.mark.parametrize("bad_mode", [0o664, 0o666, 0o620])
def test_server_refuses_group_or_world_writable_inventory(tmp_path, monkeypatch, bad_mode):
    path = _write_inventory(tmp_path, content=SAMPLE_DEVICES, mode=bad_mode)
    _set_inventory(tmp_path, monkeypatch, path)
    with pytest.raises(
        server.NewtonError,
        match=r"inventory file must not be group- or world-writable",
    ):
        server.load_inventory()


def test_server_refuses_inventory_symlink(tmp_path, monkeypatch):
    real = tmp_path / "real-inventory.toml"
    real.write_text(SAMPLE_DEVICES)
    real.chmod(0o644)
    link = tmp_path / "devices.toml"
    link.symlink_to(real)
    _set_inventory(tmp_path, monkeypatch, link)
    with pytest.raises(
        server.NewtonError,
        match=r"inventory file must be a regular file, not a symlink",
    ):
        server.load_inventory()


def test_server_refuses_inventory_directory(tmp_path, monkeypatch):
    directory = tmp_path / "devices.toml"
    directory.mkdir()
    _set_inventory(tmp_path, monkeypatch, directory)
    with pytest.raises(
        server.NewtonError,
        match=r"inventory file must be a regular file, not a symlink",
    ):
        server.load_inventory()


def test_server_refuses_inventory_not_owned_by_euid(tmp_path, monkeypatch):
    path = _write_inventory(tmp_path, content=SAMPLE_DEVICES, mode=0o644)
    monkeypatch.setattr(inventory_file, "_effective_uid", lambda: path.stat().st_uid + 1)
    _set_inventory(tmp_path, monkeypatch, path)
    with pytest.raises(
        server.NewtonError,
        match=r"inventory file must be owned by the user running the MCP server",
    ):
        server.load_inventory()


def test_server_missing_inventory_keeps_old_message(tmp_path, monkeypatch):
    _set_inventory(tmp_path, monkeypatch, tmp_path / "no-such-file.toml")
    with pytest.raises(server.NewtonError, match=r"^inventory file not found:"):
        server.load_inventory()


# ---- scans.py: load_vantages -------------------------------------------------


def test_scans_accepts_inventory_mode_0600(tmp_path, monkeypatch):
    content = _vantage_inputs(tmp_path, SAMPLE_VANTAGES)
    path = _write_inventory(tmp_path, content=content, mode=0o600)
    _set_inventory(tmp_path, monkeypatch, path)
    assert "inside-a" in scans.load_vantages()


def test_scans_accepts_inventory_mode_0644(tmp_path, monkeypatch):
    content = _vantage_inputs(tmp_path, SAMPLE_VANTAGES)
    path = _write_inventory(tmp_path, content=content, mode=0o644)
    _set_inventory(tmp_path, monkeypatch, path)
    assert "inside-a" in scans.load_vantages()


@pytest.mark.parametrize("bad_mode", [0o664, 0o666, 0o620])
def test_scans_refuses_group_or_world_writable_inventory(tmp_path, monkeypatch, bad_mode):
    content = _vantage_inputs(tmp_path, SAMPLE_VANTAGES)
    path = _write_inventory(tmp_path, content=content, mode=bad_mode)
    _set_inventory(tmp_path, monkeypatch, path)
    with pytest.raises(
        scans.ScanError,
        match=r"inventory file must not be group- or world-writable",
    ):
        scans.load_vantages()


def test_scans_refuses_inventory_symlink(tmp_path, monkeypatch):
    content = _vantage_inputs(tmp_path, SAMPLE_VANTAGES)
    real = tmp_path / "real-inventory.toml"
    real.write_text(content)
    real.chmod(0o644)
    link = tmp_path / "devices.toml"
    link.symlink_to(real)
    _set_inventory(tmp_path, monkeypatch, link)
    with pytest.raises(
        scans.ScanError,
        match=r"inventory file must be a regular file, not a symlink",
    ):
        scans.load_vantages()


def test_scans_refuses_inventory_directory(tmp_path, monkeypatch):
    _vantage_inputs(tmp_path, SAMPLE_VANTAGES)
    directory = tmp_path / "devices.toml"
    directory.mkdir()
    _set_inventory(tmp_path, monkeypatch, directory)
    with pytest.raises(
        scans.ScanError,
        match=r"inventory file must be a regular file, not a symlink",
    ):
        scans.load_vantages()


def test_scans_refuses_inventory_not_owned_by_euid(tmp_path, monkeypatch):
    content = _vantage_inputs(tmp_path, SAMPLE_VANTAGES)
    path = _write_inventory(tmp_path, content=content, mode=0o644)
    monkeypatch.setattr(inventory_file, "_effective_uid", lambda: path.stat().st_uid + 1)
    _set_inventory(tmp_path, monkeypatch, path)
    with pytest.raises(
        scans.ScanError,
        match=r"inventory file must be owned by the user running the MCP server",
    ):
        scans.load_vantages()


def test_scans_missing_inventory_keeps_old_message(tmp_path, monkeypatch):
    _set_inventory(tmp_path, monkeypatch, tmp_path / "no-such-file.toml")
    with pytest.raises(scans.ScanError, match=r"^inventory file not found:"):
        scans.load_vantages()

def test_check_fails_closed_on_lstat_error_other_than_missing(tmp_path, monkeypatch):
    path = tmp_path / "devices.toml"
    path.write_text("")

    def boom(self):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(type(path), "lstat", boom)
    assert "cannot be inspected" in (inventory_file.check(path) or "")


def test_writable_refusal_says_how_to_fix_it(tmp_path):
    path = tmp_path / "devices.toml"
    path.write_text("")
    path.chmod(0o664)
    assert f"chmod go-w {path}" in (inventory_file.check(path) or "")
