"""The 1.4 write setup and the 1.3 collector setup as a template and a fill
(the maintainer's decisions R1 and on open point 34 of DESIGN-1.5, 2026-11-16).

The AD build's stage 8 runs both setups on DC1 through the setup
generators' own code paths: the build helper gets each template from the
bootstrap and fills it from the plan bytes.  The owner's scripts stay byte
for byte what generators without the refactor write: the golden files of
``fixtures/setup_golden`` were written by generators without it (the audit one
before the refactor, the write one by the main line's generator after its
domain-device change), with stub files, and the tests here compare the
refactored output with them.

The build variants differ from the owner's scripts in two places only: the
write setup reads K from the build helper's install root instead of asking
for the passphrase, and neither has an sshd restart step of its own.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from newton_mcp.ad import forbidden, setupgen, setupgen_write
from newton_mcp.ad.build import bootstrap

GOLDEN = Path(__file__).resolve().parent / "fixtures" / "setup_golden"

KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"
DOMAIN = "win.newton.test"
DEVICE = "windc1"
HOST = "windc1.win.newton.test"
OUS = ["OU=Users,DC=win,DC=newton,DC=test", "OU=IT Staff,DC=win,DC=newton,DC=test"]

PLACEHOLDER_RE = re.compile(r"@@[A-Z_]+@@")


@pytest.fixture
def stubs(monkeypatch: pytest.MonkeyPatch) -> bytes:
    """The stub files the golden scripts were written with."""
    monkeypatch.setattr(setupgen_write, "WRITE_HELPER_PATH", GOLDEN / "write-stub.ps1")
    monkeypatch.setattr(setupgen, "COLLECTOR_PATH", GOLDEN / "collector-stub.ps1")
    monkeypatch.setattr(setupgen, "QUERIES_PATH", GOLDEN / "queries-stub.json")
    monkeypatch.setattr(forbidden, "dump_json", lambda: b'{"forbidden": []}\n')
    return (GOLDEN / "write-stub.ps1").read_bytes()


def _golden(name: str) -> str:
    return (GOLDEN / name).read_bytes().decode("utf-8")


def test_the_1_4_windows_write_script_is_byte_for_byte_the_golden(stubs: bytes) -> None:
    got = setupgen_write.windows_write_script(domain=DOMAIN, pubkey=KEY, device=DEVICE, host=HOST, ous=OUS)
    assert got == _golden("windows-write-1.4.ps1")


def test_the_1_3_windows_script_is_byte_for_byte_the_golden(stubs: bytes) -> None:
    got = setupgen.windows_script(domain=DOMAIN, pubkey=KEY, device=DEVICE, host=HOST)
    assert got == _golden("windows-audit-1.3.ps1")


def test_the_1_4_script_is_its_template_filled(stubs: bytes) -> None:
    filled = setupgen_write.fill_windows_write(
        setupgen_write.windows_write_template(),
        domain=DOMAIN, device=DEVICE, host=HOST, ous=OUS, pubkey=KEY, helper=stubs,
    )
    assert filled == _golden("windows-write-1.4.ps1")


def test_the_1_3_script_is_its_template_filled(stubs: bytes) -> None:
    filled = setupgen.fill_windows(setupgen.windows_template(), domain=DOMAIN, device=DEVICE, host=HOST, pubkey=KEY)
    assert filled == _golden("windows-audit-1.3.ps1")


@pytest.mark.parametrize("build", [False, True])
def test_the_write_template_leaves_exactly_the_fill_placeholders(stubs: bytes, build: bool) -> None:
    template = setupgen_write.windows_write_template(build=build)
    assert set(PLACEHOLDER_RE.findall(template)) == set(setupgen_write.WRITE_FILL_FIELDS)


@pytest.mark.parametrize("build", [False, True])
def test_the_collector_template_leaves_exactly_the_fill_placeholders(stubs: bytes, build: bool) -> None:
    template = setupgen.windows_template(build=build)
    assert set(PLACEHOLDER_RE.findall(template)) == set(setupgen.FILL_FIELDS)


def _steps(text: str) -> list[str]:
    return re.findall(r"^Write-Host 'Step [0-9]+: [^']*'$", text, re.MULTILINE)


def test_the_build_write_variant_reads_k_and_has_no_restart(stubs: bytes) -> None:
    owner = setupgen_write.windows_write_template()
    build = setupgen_write.windows_write_template(build=True)
    assert "Read-Host" in owner
    assert "Read-Host" not in build
    assert "Get-ApprovalKeyHex $passphrase" not in build
    assert "$BuildKeyPath = 'C:\\ProgramData\\Newton\\ad-build\\key.hex'" in build
    assert setupgen_write.BUILD_KEY_FILE == bootstrap.KEY_FILE
    assert "Register-ScheduledTask -TaskName $RestartTask" in owner
    assert "Register-ScheduledTask" not in build
    assert "Restart-Service" not in build
    assert _steps(build) == [s for s in _steps(owner) if "sshd restart" not in s]
    # Everything but the key step's prompt and the restart step is the
    # owner's text: the build template is the owner's with the prompt
    # part replaced, the words about the key mismatch replaced and the
    # restart step dropped.
    ask = setupgen_write._WIN_STEP_KEY_ASK
    assert owner.replace(ask, setupgen_write._WIN_STEP_KEY_BUILD).replace(
        setupgen_write.WIN_KEY_MISMATCH_OWNER, setupgen_write.WIN_KEY_MISMATCH_BUILD
    ).replace("\n" + setupgen_write._WIN_STEP_RESTART, "") == build


def test_the_build_write_variant_says_the_truth_about_a_different_key(stubs: bytes) -> None:
    """The build variant asks for no passphrase, so the owner's words about the
    passphrase typed now would be a lie there, and the setup stops with its
    earlier steps already run."""
    owner = setupgen_write.windows_write_template()
    build = setupgen_write.windows_write_template(build=True)
    assert "typed now" not in build
    assert "Nothing was changed" not in build
    assert setupgen_write.WIN_KEY_MISMATCH_BUILD in build
    assert "typed now" in owner
    # The owner's script ran the account and delegation steps before the
    # key step, so it must not say nothing was changed either.
    assert "Nothing was changed" not in owner
    assert "its earlier steps (the newton-ops account and its delegation) have already run" in owner


def test_the_build_collector_variant_has_no_restart(stubs: bytes) -> None:
    owner = setupgen.windows_template()
    build = setupgen.windows_template(build=True)
    assert "Register-ScheduledTask" in owner
    assert "Register-ScheduledTask" not in build
    assert "Restart-Service" not in build
    assert owner.replace("\n" + setupgen._STEP_RESTART, "") == build
