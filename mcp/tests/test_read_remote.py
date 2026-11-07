"""Design 7.2 rows script_env and read: the new environment variables and
the remote command line per auth mode (PROG prefix, key mode unquoted with
IdentitiesOnly/known-hosts options, password mode shlex-quoted so root's
shell cannot glob `[0]`)."""

import subprocess

import pytest

import newton_mcp.server as server

PROG = server.PROG


@pytest.fixture
def key_device(tmp_path, monkeypatch):
    key = tmp_path / "newton-key"
    key.write_text("FAKE-KEY-FOR-TESTS\n")
    key.chmod(0o600)
    known = tmp_path / "known-hosts"
    known.write_text("")
    inventory = tmp_path / "devices.toml"
    inventory.write_text(
        '[devices.quasar]\nplatform="openwrt"\nhost="192.0.2.1"\nuser="root"\n'
        f'key_file="{key}"\nknown_hosts="{known}"\nwan_zones=["wan","wan2"]\n'
    )
    monkeypatch.setenv("NEWTON_INVENTORY", str(inventory))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    return tmp_path


def test_script_env_carries_expect_and_key_vars(key_device):
    svc = server.NewtonService()
    env = svc.script_env(svc.device("quasar"))
    assert env["OWRT_EXPECT_DEVICE"] == "quasar"
    assert env["OWRT_EXPECT_PROFILE"] == "prod"
    assert env["OWRT_SSH_KEY"].endswith("newton-key")
    assert env["OWRT_KNOWN_HOSTS"].endswith("known-hosts")


def test_script_env_omits_key_vars_when_absent(tmp_path, monkeypatch):
    inventory = tmp_path / "devices.toml"
    inventory.write_text(
        '[devices.quasar]\nplatform="openwrt"\nhost="192.0.2.1"\nuser="root"\n'
    )
    monkeypatch.setenv("NEWTON_INVENTORY", str(inventory))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    svc = server.NewtonService()
    env = svc.script_env(svc.device("quasar"))
    assert "OWRT_SSH_KEY" not in env
    assert "OWRT_KNOWN_HOSTS" not in env
    assert env["OWRT_EXPECT_DEVICE"] == "quasar"
    assert env["OWRT_EXPECT_PROFILE"] == "prod"


def _capture_run(monkeypatch):
    seen = {}

    def fake_run(args, **kwargs):
        seen.update(args=args, kwargs=kwargs)
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(server.subprocess, "run", fake_run)
    return seen


def test_key_mode_sends_prog_prefixed_tokens_unquoted(key_device, monkeypatch):
    seen = _capture_run(monkeypatch)
    server.newton_read("quasar", "uci get wireless.@wifi-iface[0].ssid")
    args = seen["args"]
    assert args[-3:] == [
        "--",
        "root@192.0.2.1",
        f"{PROG} read uci get wireless.@wifi-iface[0].ssid",
    ]
    joined = " ".join(args)
    assert "-i" in args and args[args.index("-i") + 1].endswith("newton-key")
    assert "IdentitiesOnly=yes" in joined
    assert "StrictHostKeyChecking=yes" in joined
    assert "UserKnownHostsFile=" in joined


def test_key_mode_without_key_file_has_no_identity_options(tmp_path, monkeypatch):
    inventory = tmp_path / "devices.toml"
    inventory.write_text(
        '[devices.quasar]\nplatform="openwrt"\nhost="192.0.2.1"\nuser="root"\n'
    )
    monkeypatch.setenv("NEWTON_INVENTORY", str(inventory))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    seen = _capture_run(monkeypatch)
    server.newton_read("quasar", "uci show")
    joined = " ".join(seen["args"])
    assert seen["args"][-1] == f"{PROG} read uci show"
    assert "IdentitiesOnly" not in joined
    assert "UserKnownHostsFile" not in joined


def test_password_mode_shlex_quotes_the_whole_command(tmp_path, monkeypatch):
    password = tmp_path / "password"
    password.write_text("made-up-password\n")
    password.chmod(0o600)
    inventory = tmp_path / "devices.toml"
    inventory.write_text(
        '[devices.quasar]\nplatform="openwrt"\nhost="192.0.2.1"\nuser="root"\n'
        f'auth="password"\npassword_file="{password}"\n'
    )
    monkeypatch.setenv("NEWTON_INVENTORY", str(inventory))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    seen = _capture_run(monkeypatch)
    server.newton_read("quasar", "uci get wireless.@wifi-iface[0].ssid")
    import shlex
    assert seen["args"][-1] == shlex.join(
        [PROG, "read", "uci", "get", "wireless.@wifi-iface[0].ssid"]
    )
    assert seen["args"][-1].endswith(
        "'wireless.@wifi-iface[0].ssid'"
    )  # the [0] token is quoted; root's shell cannot glob it
