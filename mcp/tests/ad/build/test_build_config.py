"""The owner's build config and the helper transport (PLAN-1.5 task 8;
DESIGN-1.5, open point 6 of task 7).

The config names each server's ``newton-build`` login and its checkpoint
target; its schema is exact and it holds no secret (the keys, the pinned
host keys and the Proxmox token secret are files it names).  The transport
sends one JSON request on stdin over the locked ssh runner of the
repository and checks the answer against the contract.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from newton_mcp.ad.build import checkpoint as build_checkpoint
from newton_mcp.ad.build import config as build_config
from newton_mcp.ad.build import transport as build_transport
from newton_mcp.adapters.vendor_write import SessionSpec
from newton_mcp.vendor_change import RunOut


def _write(tmp_path: Path, text: str, mode: int = 0o600) -> Path:
    path = tmp_path / "ad-build.toml"
    path.write_text(text, encoding="utf-8")
    path.chmod(mode)
    return path


BASE = """version = 1

[servers.build1]
host = "192.0.2.11"
port = 22
key_file = "/home/owner/.ssh/newton-build"
known_hosts = "/home/owner/.config/newton/ad-build.known_hosts"

[servers.build1.proxmox]
api = "https://pve.example.test:8006/api2/json"
node = "pve"
vmid = "8301"
token_id = "newton@pve!build"
token_file = "/home/owner/.config/newton/pve-build.token"
ca_file = "/home/owner/.config/newton/pve-ca.pem"

[servers.build2]
host = "192.0.2.12"
port = 2222
key_file = "/home/owner/.ssh/newton-build"
known_hosts = "/home/owner/.config/newton/ad-build.known_hosts"

[servers.build2.hyperv]
host = "hvhost.example.test"
port = 22
user = "hv-checkpoint"
key_file = "/home/owner/.ssh/hv-checkpoint"
known_hosts = "/home/owner/.config/newton/hv.known_hosts"
vm = "BUILD2"
"""


def test_a_config_names_the_logins_and_the_targets(tmp_path: Path) -> None:
    loaded = build_config.load_config(_write(tmp_path, BASE))
    helper = loaded.helpers["build1"]
    assert (helper.host, helper.port, helper.user, helper.platform) == ("192.0.2.11", 22, "newton-build", "ad-windows-write")
    assert loaded.helpers["build2"].port == 2222
    pve = loaded.proxmox["build1"]
    assert (pve.node, pve.vmid, pve.token_id) == ("pve", "8301", "newton@pve!build")
    hv, key_file, known = loaded.hyperv["build2"]
    assert hv.vm == "BUILD2"
    assert hv.ssh[0] == "ssh" and hv.ssh[-1] == "hv-checkpoint@hvhost.example.test"
    assert "BatchMode=yes" in hv.ssh and "StrictHostKeyChecking=yes" in hv.ssh
    assert f"UserKnownHostsFile={known}" in hv.ssh
    assert str(key_file) in hv.ssh and "IdentitiesOnly=yes" in hv.ssh


def test_the_hyperv_argv_holds_the_repositorys_locked_ssh_options(tmp_path: Path) -> None:
    """F5 of the part B review: the Hyper-V login's argv is built by hand
    from the config's fields; it must equal the repository's locked options
    (``ssh_cli.base_argv``) for the same host, port, key and known_hosts,
    then the destination."""
    from newton_mcp.adapters import ssh_cli

    key = tmp_path / "hv-key"
    known = tmp_path / "hv.known_hosts"
    key.write_text("key", encoding="ascii")
    known.write_text("host key", encoding="ascii")
    text = BASE.replace('key_file = "/home/owner/.ssh/hv-checkpoint"', f'key_file = "{key}"').replace(
        'known_hosts = "/home/owner/.config/newton/hv.known_hosts"', f'known_hosts = "{known}"'
    )
    hv, _, _ = build_config.load_config(_write(tmp_path, text)).hyperv["build2"]
    host = hv.ssh[-1].split("@", 1)[1]
    port = int(hv.ssh[hv.ssh.index("-p") + 1])
    target = build_transport.HelperTarget(name="hv", host=host, port=port, key_file=key, known_hosts=known)
    assert list(hv.ssh[:-1]) == ssh_cli.base_argv(target)


def test_the_default_path_is_beside_the_inventory(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NEWTON_AD_BUILD_CONFIG", raising=False)
    assert build_config.config_path() == Path("~/.config/newton/ad-build.toml").expanduser()


@pytest.mark.parametrize(
    "edit",
    [
        lambda t: t.replace('token_id = "newton@pve!build"', 'token_id = "newton@pve!build"\ntoken_secret = "x"'),
        lambda t: t.replace('port = 2222', 'port = 2222\npassword = "x"'),
        lambda t: t.replace("version = 1", "version = 2"),
        lambda t: t.replace('key_file = "/home/owner/.ssh/newton-build"', 'key_file = "relative/key"', 1),
        lambda t: t.replace('port = 22\nkey_file', 'port = "22"\nkey_file', 1),
        lambda t: t.replace('host = "192.0.2.11"', 'host = "192.0.2.11; rm"'),
        lambda t: t.replace('vm = "BUILD2"', 'vm = "BUILD2 *"'),
        lambda t: t.replace('vmid = "8301"', 'vmid = 8301'),
        lambda t: t.replace('user = "hv-checkpoint"', 'user = "-oProxyCommand=x"'),
        lambda t: t.replace("[servers.build2.hyperv]", "[servers.build1.hyperv]\nhost = \"h\"\nport = 22\nuser = \"u\"\nkey_file = \"/k\"\nknown_hosts = \"/h\"\nvm = \"V\"\n\n[servers.build2.hyperv]"),
        lambda t: t.replace("[servers.build1]", "[servers.Build1]", 1),
        lambda t: t + "\n[extra]\nx = 1\n",
    ],
    ids=[
        "token-secret", "password", "version", "relative-path", "port-text", "host-grammar",
        "vm-grammar", "vmid-int", "hv-user-option", "two-hypervisors", "device-grammar", "unknown-table",
    ],
)
def test_a_config_outside_its_schema_is_refused(tmp_path: Path, edit: Any) -> None:
    with pytest.raises(build_config.BuildConfigError):
        build_config.load_config(_write(tmp_path, edit(BASE)))


def test_the_refusal_names_the_key_and_never_a_value(tmp_path: Path) -> None:
    text = BASE.replace('token_id = "newton@pve!build"', 'token_id = "newton@pve!build"\ntoken_secret = "s3cr3t-value"')
    with pytest.raises(build_config.BuildConfigError) as caught:
        build_config.load_config(_write(tmp_path, text))
    assert "s3cr3t-value" not in str(caught.value)


@pytest.mark.parametrize("mode", [0o620, 0o602, 0o666])
def test_a_config_another_user_may_write_is_refused(tmp_path: Path, mode: int) -> None:
    with pytest.raises(build_config.BuildConfigError):
        build_config.load_config(_write(tmp_path, BASE, mode))


def test_a_missing_config_is_refused(tmp_path: Path) -> None:
    with pytest.raises(build_config.BuildConfigError):
        build_config.load_config(tmp_path / "absent.toml")


def test_a_symlinked_config_is_refused(tmp_path: Path) -> None:
    real = _write(tmp_path, BASE)
    link = tmp_path / "link.toml"
    os.symlink(real, link)
    with pytest.raises(build_config.BuildConfigError):
        build_config.load_config(link)


def test_the_real_adapters_refuse_a_dc_checkpoint_without_a_helper_transport(tmp_path: Path) -> None:
    """The DC reads go through the server's helper (``HelperDcReads``, part
    B0 of task 8); adapters built from the config with no transport to the
    helper have no way to read the DC, so a DC checkpoint never verifies."""
    adapters = build_config.build_adapters(build_config.load_config(_write(tmp_path, BASE)))
    server = {"device": "build1", "role": "dc1", "hostname": "DC1", "checkpoint": "proxmox"}
    with pytest.raises(build_checkpoint.CheckpointUnverified):
        build_checkpoint.require_verified(
            adapters, server, {"name": "n", "id": "UPID:x"}, "dc", stage="3", not_before=1797000000
        )


# --------------------------------------------------------------------------
# the transport
# --------------------------------------------------------------------------


def _target(tmp_path: Path) -> build_transport.HelperTarget:
    return build_transport.HelperTarget(
        name="build1", host="192.0.2.11", port=22, key_file=tmp_path / "k", known_hosts=tmp_path / "kh"
    )


def _request(**over: Any) -> dict[str, Any]:
    fields: dict[str, Any] = dict(
        run="a1" * 16, plan_bytes=b"newton-ad-build-v1\n", stage="0", action="status",
        token="b2" * 32, nbf=1797000000, exp=1797003600,
    )
    fields.update(over)
    return build_transport.helper_request(**fields)


def test_the_transport_sends_one_json_request_on_stdin_and_no_remote_command(tmp_path: Path) -> None:
    specs: list[SessionSpec] = []

    def runner(spec: SessionSpec) -> RunOut:
        specs.append(spec)
        return RunOut(status="ok", stdout=json.dumps({"ok": True, "status": "done", "code": "", "checks": [], "completed": {"0": 1797000000}}), stderr="", exit_code=0)

    transport = build_transport.SshHelperTransport({"build1": _target(tmp_path)}, runner_for=lambda target: runner)
    answer = transport.send("build1", _request())
    assert answer["completed"] == {"0": 1797000000}
    (spec,) = specs
    assert spec.remote == ""
    assert json.loads(spec.stdin) == _request()


def test_the_locked_ssh_argv_of_the_helper_login(tmp_path: Path) -> None:
    """The session is the repository's locked runner: BatchMode, the pinned
    host key, no agent, newton-build@host and no remote command."""
    from newton_mcp.adapters.vendor_ssh import SshSessionRunner

    (tmp_path / "k").write_text("key", encoding="ascii")
    (tmp_path / "kh").write_text("host key", encoding="ascii")
    argv = SshSessionRunner(_target(tmp_path))._argv(SessionSpec(remote="", stdin="{}"))
    assert argv[0] == "ssh" and argv[-1] == "newton-build@192.0.2.11"
    assert "BatchMode=yes" in argv and "StrictHostKeyChecking=yes" in argv
    assert f"UserKnownHostsFile={tmp_path / 'kh'}" in argv
    assert "--" not in argv


@pytest.mark.parametrize(
    "out",
    [
        RunOut(status="unreachable", stdout="", stderr="", exit_code=255),
        RunOut(status="timed_out", stdout="", stderr="", exit_code=None),
        RunOut(status="ok", stdout="", stderr="", exit_code=0),
        RunOut(status="ok", stdout='{"ok":true}', stderr="", exit_code=1),
    ],
)
def test_a_session_without_an_answer_is_unavailable(tmp_path: Path, out: RunOut) -> None:
    transport = build_transport.SshHelperTransport({"build1": _target(tmp_path)}, runner_for=lambda target: lambda spec: out)
    with pytest.raises(build_transport.HelperUnavailable):
        transport.send("build1", _request())


@pytest.mark.parametrize(
    "text",
    [
        "not json",
        "[]",
        json.dumps({"ok": True, "status": "done", "code": ""}),
        json.dumps({"ok": "yes", "status": "done", "code": "", "checks": []}),
        json.dumps({"ok": True, "status": "finished", "code": "", "checks": []}),
        json.dumps({"ok": True, "status": "done", "code": "", "checks": [{"name": "x"}]}),
        json.dumps({"ok": True, "status": "done", "code": "", "checks": [], "extra": 1}),
    ],
)
def test_an_answer_outside_the_contract_is_invalid(tmp_path: Path, text: str) -> None:
    out = RunOut(status="ok", stdout=text, stderr="", exit_code=0)
    transport = build_transport.SshHelperTransport({"build1": _target(tmp_path)}, runner_for=lambda target: lambda spec: out)
    with pytest.raises(build_transport.HelperAnswerInvalid):
        transport.send("build1", _request())


def test_only_a_status_answer_carries_completions(tmp_path: Path) -> None:
    text = json.dumps({"ok": True, "status": "done", "code": "", "checks": [], "completed": {}})
    with pytest.raises(build_transport.HelperAnswerInvalid):
        build_transport.parse_answer(text, action="run")
    assert build_transport.parse_answer(text, action="status")["completed"] == {}


@pytest.mark.parametrize(
    "over",
    [
        {"run": "A1" * 16}, {"stage": "11"}, {"action": "shell"}, {"token": "x" * 64},
        {"nbf": True}, {"exp": 1797000000}, {"checkpoint": "UPID:x"}, {"action": "checkpoint", "checkpoint": "a b"},
    ],
)
def test_a_request_the_helper_would_refuse_is_never_built(over: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        _request(**over)


def test_a_checkpoint_request_names_the_id() -> None:
    request = _request(action="checkpoint", stage="2", checkpoint="UPID:pve:1:2:3:qmsnapshot:8301:u@pve!t:")
    assert request["checkpoint"] == "UPID:pve:1:2:3:qmsnapshot:8301:u@pve!t:"
    assert set(request) == {"run", "plan", "stage", "action", "token", "nbf", "exp", "checkpoint"}


def test_the_bound_is_the_later_of_the_nbf_and_the_previous_completion() -> None:
    graph = ("0", "1", "2", "3")
    assert build_transport.journal_not_before({"1": 50, "2": 1797000500}, graph=graph, stage="3", plan_nbf=1797000000) == 1797000500
    assert build_transport.journal_not_before({"2": 1796000000}, graph=graph, stage="3", plan_nbf=1797000000) == 1797000000
    with pytest.raises(build_transport.JournalUnreadable):
        build_transport.journal_not_before({"1": 1797000500}, graph=graph, stage="3", plan_nbf=1797000000)
    with pytest.raises(build_transport.JournalUnreadable):
        build_transport.journal_not_before({}, graph=graph, stage="0", plan_nbf=1797000000)
    dc2 = ("0", "1", "7", "9")
    assert build_transport.journal_not_before({"1": 1797000900}, graph=dc2, stage="7", plan_nbf=1797000000) == 1797000900
