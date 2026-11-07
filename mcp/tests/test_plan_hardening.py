from __future__ import annotations

import json
import shlex
import subprocess

import pytest

from exhelp import explained

from newton_mcp import envelope, server


SID = "0123456789abcdef0123456789abcdef"
BASE_HASH = "b" * 64


def _resolver(configured_newton, monkeypatch):
    service = server.NewtonService()
    monkeypatch.setattr(
        service,
        "read",
        lambda device, command: {
            "exit_code": 0,
            "stdout": envelope.envelope(f"{device}:{command}", "<redacted:deadbeef>\n"),
        },
    )
    return service._resolve_placeholders


@pytest.mark.parametrize(
    "batch",
    [
        "set wireless.ap.key='<redacted'\\:'deadbeef>'",
        'set wireless.ap.key=<red"acted:"deadbeef>',
        'set wireless.ap.key="<redact"ed:deadbeef\\>',
        "set wireless.ap.key='<redac'\\ted:'deadbeef>'",
        r"set wireless.ap.key=\<redacted:deadbeef\>",
        "set wireless.ap.key='<redacted:'deadbeef'>'",
    ],
)
def test_quote_concatenated_placeholders_are_detected(configured_newton, monkeypatch, batch):
    resolved = _resolver(configured_newton, monkeypatch)("quasar", batch)
    assert resolved.startswith("# dropped placeholder:")


def test_every_returned_noncomment_token_is_placeholder_free(configured_newton, monkeypatch):
    resolve = _resolver(configured_newton, monkeypatch)
    batches = [
        "set system.x.hostname=safe\n",
        "# <redacted:deadbeef>\nset system.x.notes=safe",
        "set wireless.ap.key=<redacted:deadbeef>\nset system.x.hostname=safe",
    ]
    for batch in batches:
        resolved = resolve("quasar", batch)
        for line in resolved.splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            assert all("<redacted:" not in token for token in shlex.split(line, posix=True))


def test_mismatched_concatenated_placeholder_is_refused(configured_newton, monkeypatch):
    resolve = _resolver(configured_newton, monkeypatch)
    with pytest.raises(server.NewtonError):
        resolve("quasar", "set wireless.ap.key='<redacted'\\:'00000000>'")


def _plan_output(diff):
    return (
        "BACKUP /tmp/fake.tar (2 config files)\n"
        f"STAGED session={SID}\n"
        f"BASEHASH {BASE_HASH}\n"
        f"PROBES 0 {'a' * 64}\n"
        "PROFILE lab\n"
        "APPROVAL not-required\n"
        f"PLANDIGEST {'d' * 64}\n"
        "----- diff -----\n"
        f"{diff}\n"
        "----------------\n"
    )


def _plan_with_diff(monkeypatch, diff, batch):
    monkeypatch.setattr(
        server.NewtonService,
        "run_script",
        lambda *a, **k: subprocess.CompletedProcess([], 0, _plan_output(diff), ""),
    )
    return server.NewtonService().plan("quasar", batch, **explained(batch))


def _stored_reasons(root):
    return json.loads((root / "state" / "plans" / f"{SID}.json").read_text())["reasons"]


def test_parse_plan_maps_unknown_config_names_to_other():
    parsed = server.parse_plan(
        _plan_output("ignoreall.s.o='x'\nfirewall.r.enabled='1'\ndhcp.h.ip='192.0.2.3'")
    )
    assert parsed is not None
    assert parsed["base_hash"] == BASE_HASH
    assert parsed["touched_configs"] == ["dhcp", "firewall", "other"]


def test_unknown_config_maps_to_other_and_is_never_named_in_returned_reasons(
    configured_newton, monkeypatch
):
    planned = _plan_with_diff(monkeypatch, "ignoreall.s.o='x'", "set ignoreall.s.o=x")
    assert planned["touched_configs"] == ["other"]
    # design 5.2 unknown-package now fires (it did not before); the
    # returned reasons still never name the config: only the stored record
    # keeps the diff line, and returned_approval_reasons strips it
    assert any(reason.startswith("unknown-package: ") for reason in planned["approval_reasons"])
    for reason in planned["approval_reasons"]:
        assert "ignoreall" not in reason


def test_known_configs_keep_their_names_in_touched_configs_and_reasons(
    configured_newton, monkeypatch
):
    planned = _plan_with_diff(
        monkeypatch,
        "firewall.r.enabled='1'\nsystem.x.notes='note'",
        "set firewall.r.enabled=1",
    )
    assert planned["touched_configs"] == ["firewall", "system"]
    assert any("firewall" in reason for reason in planned["approval_reasons"])
