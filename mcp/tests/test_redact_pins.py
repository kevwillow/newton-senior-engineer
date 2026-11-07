from __future__ import annotations

import json
import re
import subprocess

import pytest

from newton_mcp import redact, server

KEY = b"k" * 32
SECRET = "ObviousFakePinSecret987"
PH = r"<redacted:[0-9a-f]{8}>"


def _run_read(monkeypatch, *, command, stdout="", stderr="", returncode=0):
    def fake_run(args, **kwargs):
        return subprocess.CompletedProcess(args, returncode, stdout, stderr)

    monkeypatch.setattr(server.subprocess, "run", fake_run)


@pytest.mark.parametrize(
    "name", ["trap_community", "read_community", "write_community", "snmp_community"]
)
@pytest.mark.parametrize("kind", ["dotted", "file"])
def test_suffix_only_community_names_are_secret(name, kind):
    if kind == "dotted":
        text = f"snmpd.x.{name}='{SECRET}'"
    else:
        text = f"config agent 'a'\n\toption {name} '{SECRET}'"
    out = redact.redact_text(text, KEY)
    assert SECRET not in out
    assert "<redacted:" in out


def test_service_level_read_redacts_stdout_and_stderr(configured_newton, monkeypatch):
    _run_read(
        monkeypatch,
        command="uci show wireless",
        stdout=f"wireless.x.key='{SECRET}'\n",
        stderr=f"uci: parse error wireless.x.key={SECRET}\n",
    )
    result = server.NewtonService().read("quasar", "uci show wireless")
    assert SECRET not in json.dumps(result)
    assert "<redacted:" in result["stdout"]["text"]
    assert "<redacted:" in result["stderr"]["text"]


@pytest.mark.parametrize(
    "stdout",
    [
        pytest.param(
            "x" * (64 * 1024 - 40) + "\n" + "PrivateKey = " + "A" * 43 + "=\n" + "tail " + "z" * 300 + "\n",
            id="private-key-line",
        ),
        pytest.param(
            "x" * (64 * 1024 - 40) + "\n" + "wg peer psk " + "A" * 43 + "=\n" + "tail " + "z" * 300 + "\n",
            id="peer-psk-line",
        ),
    ],
)
def test_wireguard_key_straddling_the_64k_cut_leaves_no_fragment(stdout, configured_newton, monkeypatch):
    _run_read(monkeypatch, command="cat /etc/config/network", stdout=stdout)
    for result in (
        server.NewtonService().read("quasar", "cat /etc/config/network"),
        server.newton_read("quasar", "cat /etc/config/network"),
    ):
        assert result["truncated"] is True
        text = result["stdout"]["text"]
        assert re.search("A{8}", text) is None


@pytest.mark.parametrize(
    "text",
    [
        f'{{"psk": [["a"], "{SECRET}"]}}',
        f'{{"psk": [{{"k": "a"}}, {{"v": "{SECRET}"}}]}}',
        f'{{"password": {{"a": {{"b": 1}}, "c": "{SECRET}"}}}}',
        f'{{"key": ["x", ["y", ["z"]], "{SECRET}"]}}',
    ],
)
def test_json_container_with_secret_after_an_inner_close(text):
    out = redact.redact_text(text, KEY)
    assert SECRET not in out
    assert re.search(r'"(?:psk|password|key)": "<redacted:[0-9a-f]{8}>"', out)
    assert redact.redact_text(out, KEY) == out
    shaped = redact.redact_text('{"psk": [["a"], ["b"]], "mode": "ap"}', KEY)
    assert re.fullmatch(r'\{"psk": "<redacted:[0-9a-f]{8}>", "mode": "ap"\}', shaped)


@pytest.mark.parametrize("name", ["pass", "pwd", "uuid", "pincode", "auth_pass", "community"])
@pytest.mark.parametrize("op", ["+=", "-=", "^="])
def test_midline_dotted_operator_placeholder_equals_plain_assignment_placeholder(name, op):
    midline = redact.redact_text(f"see wireless.x.{name}{op}'{SECRET}' ok", KEY)
    plain = redact.redact_text(f"wireless.x.{name}='{SECRET}'", KEY)
    m_mid = re.search(r"<redacted:[0-9a-f]{8}>", midline)
    m_plain = re.search(r"<redacted:[0-9a-f]{8}>", plain)
    assert m_mid is not None and m_plain is not None
    assert m_mid.group(0) == m_plain.group(0)
    assert " ok" in midline


@pytest.mark.parametrize(
    "text",
    [
        f"pass-=alpha{SECRET}x beta gamma",
        f"pwd+=alpha{SECRET}x beta gamma",
        f"wireless.x.pass-=alpha{SECRET}x beta gamma",
        f"wireless.x.uuid^=alpha{SECRET}x beta gamma",
        f"Password: alpha{SECRET}x beta gamma",
        f"token: alpha{SECRET}x beta gamma",
    ],
)
def test_line_start_forms_with_operator_redact_the_whole_line(text):
    out = redact.redact_text(text, KEY)
    for word in ("alpha", "beta", "gamma", SECRET):
        assert word not in out
    assert "<redacted:" in out
    assert "\n" not in out
