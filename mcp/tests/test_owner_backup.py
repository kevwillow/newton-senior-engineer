"""the host-side backup of a no-install router's readable UCI.

ADR-021 point 7 and the design: before Newton asks the owner to run a
script, Newton keeps a copy of the settings the script touches on the
Newton computer.  That copy is what the read-back compares against and
what the restore script is built from.

What is proved here:

  * the backup is built from the measured answers;
  * a config the router does not have is only allowed when the change
    creates that config's first section;
  * a refused answer, a transport error and a malformed answer all
    refuse the backup;
  * a window that is open on the router refuses the backup;
  * the files are mode 0600 in a mode 0700 directory, and the write is
    an atomic replace with an fsync;
  * a symlinked state path is refused;
  * a file whose sha256 does not match the manifest is refused on load;
  * the Wi-Fi key never leaves the module in a value, a message or a
    log line.
"""

from __future__ import annotations

import json
import os
import stat
import time
from pathlib import Path
from typing import Any, Callable

import pytest

from newton_mcp import owner_backup
from newton_mcp.adapters.openwrt_rpcd import RpcdCallFailed, RpcdError
from newton_mcp.owner_backup import Backup, BackupError
from newton_mcp.server import Device
import noinstall_answers
import owner_answers
from noinstall_answers import data
from owner_answers import data as firewall_data


#: The key of the Wi-Fi section of a synthetic wireless config.  It never
#: leaves the backup: the canary of the "never in a message" tests.
WIFI_KEY = "wifi-key-canary-4f1c9a2e"


# ---- the fakes -------------------------------------------------------------


class FakeSession:
    """A session that answers like the router's own web API."""

    def __init__(self, answers: dict[tuple[str, str], Any], timeout_s: int) -> None:
        self.answers = answers
        self.timeout_s = timeout_s
        self.spent = False
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def call(self, obj: str, fn: str, args: dict[str, Any] | None = None) -> Any:
        call_args = dict(args or {})
        self.calls.append((obj, fn, call_args))
        value = self.answers.get((obj, fn), self.answers.get(("*", "*"), {}))
        if callable(value):
            value = value(obj, fn, call_args)
        if isinstance(value, list):
            # a measured answer is [code] or [code, data]
            code = value[0]
            if code:
                raise RpcdCallFailed(int(code))
            return value[1] if len(value) > 1 else {}
        if isinstance(value, bool):
            raise AssertionError("a refusal code must be an int, not a bool")
        if isinstance(value, int):
            raise RpcdCallFailed(value)
        if isinstance(value, BaseException):
            raise value
        return value

    def mark_spent(self) -> None:
        self.spent = True


class FakeClient:
    """A client that hands out one session and records every login."""

    def __init__(self, answers: dict[tuple[str, str], Any]) -> None:
        self.answers = answers
        self.sessions: list[FakeSession] = []
        self.logins: list[tuple[str, str, int]] = []

    def login(self, username: str, password: str, timeout_s: int) -> FakeSession:
        self.logins.append((username, password, timeout_s))
        session = FakeSession(self.answers, timeout_s)
        self.sessions.append(session)
        return session

    def call(
        self,
        session: FakeSession,
        obj: str,
        fn: str,
        args: dict[str, Any] | None = None,
    ) -> Any:
        return session.call(obj, fn, args)


def factory(client: FakeClient) -> Callable[[Any], FakeClient]:
    def build(_device: Any) -> FakeClient:
        return client

    return build


def _measured(key: str) -> Any:
    """One measured answer of lab-r1, from either of the two files."""
    for module in (noinstall_answers, owner_answers):
        if key in module.ANSWERS:
            return module.answer(key)
    raise KeyError(key)


def _answers(extra: dict[tuple[str, str], Any] | None = None) -> dict[tuple[str, str], Any]:
    """The measured answers of lab-r1, with the extra ones on top."""
    table: dict[tuple[str, str], Any] = {
        ("file", "list"): {"entries": []},
        ("system", "board"): _measured("system.board")[1],
        ("uci", "get"): lambda obj, fn, args: _measured(
            "uci.get." + str(args.get("config", ""))
        ),
    }
    table.update(extra or {})
    return table


def _device(tmp_path: Path, **overrides: Any) -> Device:
    password = tmp_path / "rpcd-password"
    handle = os.open(str(password), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(handle, "w", encoding="utf-8") as stream:
        stream.write("synthetic-password\n")
    fields = {
        "name": "lab-r1",
        "platform": "openwrt",
        "host": "192.0.2.1",
        "user": "root",
        "profile": "lab",
        "access": "no-install",
        "https_host": "192.0.2.1",
        "https_port": 443,
        "https_spki": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "rpcd_password_file": password,
    }
    fields.update(overrides)
    return Device(**fields)


def _state(tmp_path: Path) -> Path:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    os.chmod(state, 0o700)
    return state


# ---- the taking ------------------------------------------------------------


def test_the_backup_holds_the_measured_answers() -> None:
    client = FakeClient(_answers())
    backup = owner_backup.take(
        factory(client), _device(Path("/tmp")), ["firewall", "system"]
    )
    assert backup.configs["firewall"] == firewall_data("uci.get.firewall")["values"]
    assert backup.configs["system"] == data("uci.get.system")["values"]
    assert backup.board == "qemu-standard-pc-i440fx-piix-1996"
    assert backup.missing == ()


def test_the_backup_reads_the_whole_config_and_not_the_touched_units() -> None:
    client = FakeClient(_answers())
    owner_backup.take(factory(client), _device(Path("/tmp")), ["firewall"])
    session = client.sessions[0]
    gets = [args for obj, fn, args in session.calls if obj == "uci" and fn == "get"]
    assert gets == [{"config": "firewall"}]


def test_the_backup_uses_one_fresh_short_read_only_session() -> None:
    client = FakeClient(_answers())
    owner_backup.take(factory(client), _device(Path("/tmp")), ["firewall", "system"])
    assert len(client.logins) == 1
    _user, _password, timeout_s = client.logins[0]
    assert timeout_s == owner_backup.LOGIN_TIMEOUT_S
    assert client.sessions[0].spent is True


def test_the_backup_refuses_when_a_window_is_open_on_the_router() -> None:
    client = FakeClient(
        _answers({("file", "list"): {"entries": [{"name": "dhcp", "type": "file"}]}})
    )
    with pytest.raises(BackupError) as excinfo:
        owner_backup.take(factory(client), _device(Path("/tmp")), ["firewall"])
    assert "waiting for confirmation" in str(excinfo.value)


def test_a_leftover_undo_file_names_the_way_out() -> None:
    """An undo file the router forgot about says how to get rid of it.

    After a restart of the router's web service the window is gone but
    the undo file stays for good (measured, a4m-02).  Newton still
    refuses, and it says what the owner can do about it.
    """
    old = int(time.time()) - 3600
    client = FakeClient(
        _answers(
            {
                ("file", "list"): {
                    "entries": [
                        {"name": "dhcp", "type": "file", "mtime": old}
                    ]
                }
            }
        )
    )
    with pytest.raises(BackupError) as excinfo:
        owner_backup.take(factory(client), _device(Path("/tmp")), ["firewall"])
    message = str(excinfo.value)
    assert "leftover undo file" in message, message
    assert "1 hour ago" in message, message
    assert "rm -rf /var/run/rpcd/snapshot-files" in message, message


def test_a_fresh_undo_file_keeps_the_short_message() -> None:
    """A window that is still young keeps today's message."""
    fresh = int(time.time()) - 60
    client = FakeClient(
        _answers(
            {
                ("file", "list"): {
                    "entries": [
                        {"name": "dhcp", "type": "file", "mtime": fresh}
                    ]
                }
            }
        )
    )
    with pytest.raises(BackupError) as excinfo:
        owner_backup.take(factory(client), _device(Path("/tmp")), ["firewall"])
    message = str(excinfo.value)
    assert "waiting for confirmation" in message, message
    assert "leftover undo file" not in message, message


def test_an_unreadable_mtime_keeps_the_short_message() -> None:
    """An undo file whose age cannot be read keeps today's message."""
    client = FakeClient(
        _answers(
            {
                ("file", "list"): {
                    "entries": [{"name": "dhcp", "type": "file"}]
                }
            }
        )
    )
    with pytest.raises(BackupError) as excinfo:
        owner_backup.take(factory(client), _device(Path("/tmp")), ["firewall"])
    message = str(excinfo.value)
    assert "waiting for confirmation" in message, message
    assert "leftover undo file" not in message, message


def test_a_config_the_router_does_not_have_is_refused() -> None:
    # the measured answer for a config with no file on lab-r1 is [4]
    client = FakeClient(_answers())
    with pytest.raises(BackupError) as excinfo:
        owner_backup.take(factory(client), _device(Path("/tmp")), ["wireless"])
    assert "nothing to back up" in str(excinfo.value)


def test_a_config_the_router_does_not_have_is_allowed_when_the_change_creates_it() -> None:
    client = FakeClient(_answers())
    backup = owner_backup.take(
        factory(client), _device(Path("/tmp")), ["wireless"], creates=["wireless"]
    )
    assert backup.missing == ("wireless",)
    assert "wireless" not in backup.configs


def test_an_unknown_config_is_refused_like_a_refused_answer() -> None:
    # the measured answer for an unknown config is [6], not [4]
    client = FakeClient(_answers())
    with pytest.raises(BackupError) as excinfo:
        owner_backup.take(factory(client), _device(Path("/tmp")), ["nosuchconfig"])
    assert "cannot be read" in str(excinfo.value)


def test_a_refused_answer_refuses_the_backup() -> None:
    client = FakeClient(_answers({("uci", "get"): 6}))
    with pytest.raises(BackupError) as excinfo:
        owner_backup.take(factory(client), _device(Path("/tmp")), ["firewall"])
    assert "cannot be read" in str(excinfo.value)


def test_a_transport_error_refuses_the_backup() -> None:
    client = FakeClient(_answers({("uci", "get"): RpcdError("the router went away")}))
    with pytest.raises(BackupError) as excinfo:
        owner_backup.take(factory(client), _device(Path("/tmp")), ["firewall"])
    assert "cannot be read" in str(excinfo.value)


def test_a_malformed_answer_refuses_the_backup() -> None:
    client = FakeClient(_answers({("uci", "get"): {"no": "values"}}))
    with pytest.raises(BackupError) as excinfo:
        owner_backup.take(factory(client), _device(Path("/tmp")), ["firewall"])
    assert "cannot be read" in str(excinfo.value)


def test_a_login_failure_refuses_the_backup() -> None:
    class Refusing(FakeClient):
        def login(self, username: str, password: str, timeout_s: int) -> FakeSession:
            raise RpcdCallFailed(6)

    with pytest.raises(BackupError) as excinfo:
        owner_backup.take(factory(Refusing(_answers())), _device(Path("/tmp")), ["firewall"])
    assert "refused the login" in str(excinfo.value)


def test_the_backup_names_the_config_it_could_not_read() -> None:
    client = FakeClient(_answers({("uci", "get"): 6}))
    with pytest.raises(BackupError) as excinfo:
        owner_backup.take(factory(client), _device(Path("/tmp")), ["firewall"])
    assert "firewall" in str(excinfo.value)


def test_the_backup_does_not_cover_the_configs_newton_cannot_read() -> None:
    from newton_mcp import owner_ops

    for config in ("rpcd", "uhttpd", "dropbear", "luci"):
        assert config not in owner_ops.ALLOWED_CONFIGS


def test_the_module_says_honestly_what_the_backup_is() -> None:
    doc = owner_backup.__doc__ or ""
    assert "STRUCTURED copy" in doc
    assert "not a byte copy" in doc
    assert "rpcd" in doc and "uhttpd" in doc and "dropbear" in doc


# ---- the writing -----------------------------------------------------------


def _backup(tmp_path: Path, **overrides: Any) -> Backup:
    configs = {
        "dhcp": data("uci.get.dhcp")["values"],
        "firewall": firewall_data("uci.get.firewall")["values"],
    }
    return Backup(
        configs=configs,
        board="qemu-standard-pc-i440fx-piix-1996",
        **overrides,
    )


def test_the_backup_is_written_under_the_owner_scripts_directory(tmp_path: Path) -> None:
    state = _state(tmp_path)
    manifest = owner_backup.write(state, "a" * 32, _backup(tmp_path))
    directory = state / "owner-scripts" / ("a" * 32) / "backup"
    assert (directory / "manifest.json").exists()
    assert (directory / "firewall.json").exists()
    assert manifest["count"] == 2
    assert manifest["sid"] == "a" * 32
    assert manifest["board"] == "qemu-standard-pc-i440fx-piix-1996"


def test_the_backup_files_are_private(tmp_path: Path) -> None:
    state = _state(tmp_path)
    owner_backup.write(state, "a" * 32, _backup(tmp_path))
    directory = state / "owner-scripts" / ("a" * 32) / "backup"
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert stat.S_IMODE((state / "owner-scripts").stat().st_mode) == 0o700
    for name in ("manifest.json", "firewall.json", "dhcp.json"):
        assert stat.S_IMODE((directory / name).stat().st_mode) == 0o600


def test_the_backup_write_fsyncs_and_replaces_atomically(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = _state(tmp_path)
    calls: list[str] = []
    real_fsync = os.fsync
    real_replace = os.replace

    def spy_fsync(fd: int) -> None:
        calls.append("fsync")
        return real_fsync(fd)

    def spy_replace(src: Any, dst: Any) -> None:
        calls.append("replace")
        return real_replace(src, dst)

    monkeypatch.setattr(owner_backup.os, "fsync", spy_fsync)
    monkeypatch.setattr(owner_backup.os, "replace", spy_replace)
    owner_backup.write(state, "a" * 32, _backup(tmp_path))
    assert "fsync" in calls
    assert "replace" in calls


def test_the_backup_write_leaves_no_temporary_file_behind(tmp_path: Path) -> None:
    state = _state(tmp_path)
    owner_backup.write(state, "a" * 32, _backup(tmp_path))
    directory = state / "owner-scripts" / ("a" * 32) / "backup"
    assert sorted(p.name for p in directory.iterdir()) == [
        "dhcp.json",
        "firewall.json",
        "manifest.json",
    ]


def test_a_symlinked_state_path_is_refused(tmp_path: Path) -> None:
    real = tmp_path / "real-state"
    real.mkdir(mode=0o700)
    os.chmod(real, 0o700)
    link = tmp_path / "link-state"
    link.symlink_to(real, target_is_directory=True)
    with pytest.raises(BackupError) as excinfo:
        owner_backup.write(link, "a" * 32, _backup(tmp_path))
    assert "symlink" in str(excinfo.value)


def test_a_group_writable_state_directory_is_refused(tmp_path: Path) -> None:
    state = _state(tmp_path)
    os.chmod(state, 0o770)
    with pytest.raises(BackupError) as excinfo:
        owner_backup.write(state, "a" * 32, _backup(tmp_path))
    assert "writable" in str(excinfo.value)


# ---- the loading -----------------------------------------------------------


def test_the_backup_loads_back_with_every_sha256_checked(tmp_path: Path) -> None:
    state = _state(tmp_path)
    written = _backup(tmp_path)
    owner_backup.write(state, "a" * 32, written)
    loaded = owner_backup.load(state, "a" * 32)
    assert loaded.configs == written.configs
    assert loaded.board == written.board
    assert loaded.sid == "a" * 32


def test_a_manifest_mismatch_is_refused_on_load(tmp_path: Path) -> None:
    state = _state(tmp_path)
    owner_backup.write(state, "a" * 32, _backup(tmp_path))
    target = state / "owner-scripts" / ("a" * 32) / "backup" / "firewall.json"
    target.write_bytes(target.read_bytes().replace(b"lab", b"evil"))
    with pytest.raises(BackupError) as excinfo:
        owner_backup.load(state, "a" * 32)
    assert "does not match its manifest" in str(excinfo.value)


def test_a_missing_backup_is_refused_on_load(tmp_path: Path) -> None:
    state = _state(tmp_path)
    with pytest.raises(BackupError) as excinfo:
        owner_backup.load(state, "a" * 32)
    assert "missing" in str(excinfo.value)


def test_an_unreadable_backup_is_refused_on_load(tmp_path: Path) -> None:
    state = _state(tmp_path)
    owner_backup.write(state, "a" * 32, _backup(tmp_path))
    target = state / "owner-scripts" / ("a" * 32) / "backup" / "firewall.json"
    target.write_bytes(b"not json at all")
    with pytest.raises(BackupError):
        owner_backup.load(state, "a" * 32)


# ---- the secret ------------------------------------------------------------


def _wireless_backup() -> Backup:
    return Backup(
        configs={
            "wireless": {
                "cfg000001": {
                    ".anonymous": True,
                    ".index": 0,
                    ".name": "cfg000001",
                    ".type": "wifi-device",
                },
                "radio0": {
                    ".anonymous": False,
                    ".index": 1,
                    ".name": "radio0",
                    ".type": "wifi-iface",
                    "encryption": "psk2",
                    "key": WIFI_KEY,
                },
            }
        },
        board="qemu-standard-pc-i440fx-piix-1996",
    )


def test_the_wifi_key_is_in_the_backup_file_on_disk(tmp_path: Path) -> None:
    state = _state(tmp_path)
    owner_backup.write(state, "a" * 32, _wireless_backup())
    target = state / "owner-scripts" / ("a" * 32) / "backup" / "wireless.json"
    assert WIFI_KEY in target.read_text(encoding="utf-8")


def test_the_wifi_key_is_not_in_the_manifest_that_leaves_the_module(
    tmp_path: Path,
) -> None:
    state = _state(tmp_path)
    manifest = owner_backup.write(state, "a" * 32, _wireless_backup())
    assert WIFI_KEY not in json.dumps(manifest)


def test_the_wifi_key_is_not_in_a_message(tmp_path: Path) -> None:
    state = _state(tmp_path)
    owner_backup.write(state, "a" * 32, _wireless_backup())
    target = state / "owner-scripts" / ("a" * 32) / "backup" / "wireless.json"
    target.write_bytes(target.read_bytes().replace(WIFI_KEY.encode(), b"broken"))
    try:
        owner_backup.load(state, "a" * 32)
    except BackupError as exc:
        assert WIFI_KEY not in str(exc)
    else:
        raise AssertionError("a changed backup must be refused")


def test_the_wifi_key_is_not_in_the_name_of_the_backup(tmp_path: Path) -> None:
    state = _state(tmp_path)
    manifest = owner_backup.write(state, "a" * 32, _wireless_backup())
    assert WIFI_KEY not in manifest["sid"]
    assert WIFI_KEY not in manifest["board"]
    for name in manifest["files"]:
        assert WIFI_KEY not in name


class RealShapeClient(FakeClient):
    """A client shaped like ``RpcdClient``: ``login`` returns a real
    ``RpcdSession`` (which has no ``call``), and every call goes through
    ``client.call(session, ...)``."""

    def login(self, username: str, password: str, timeout_s: int) -> Any:
        import time as _time

        from newton_mcp.adapters import openwrt_rpcd as rpcd

        self.logins.append((username, password, timeout_s))
        fake = FakeSession(self.answers, timeout_s)
        self.sessions.append(fake)
        real = rpcd.RpcdSession(
            id="0" * 31 + str(len(self.sessions)),
            expires_at=_time.time() + timeout_s,
            acls={},
            timeout_s=timeout_s,
        )
        self._fakes = getattr(self, "_fakes", {})
        self._fakes[real.id] = fake
        return real

    def call(self, session: Any, obj: str, fn: str, args: dict[str, Any] | None = None) -> Any:
        return self._fakes[session.id].call(obj, fn, args)


def test_the_backup_works_with_the_real_session_type() -> None:
    """(lab-r1) the backup called ``session.call``,
    which the real ``RpcdSession`` does not have; the fakes hid it, and
    every owner plan failed on a real router before any script was made."""
    client = RealShapeClient(_answers())
    backup = owner_backup.take(factory(client), _device(Path("/tmp")), ["system"])
    assert "system" in backup.configs
