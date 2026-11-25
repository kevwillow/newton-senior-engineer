"""The bootstrap installs the helper where the helper reads its install
(PLAN-1.5 task 8; DESIGN-1.5 open point 23 of task 8).

The helper reads K (``key.hex``), the device name (``device.txt``) and its
journal under its install root ``C:\\ProgramData\\Newton\\ad-build``: the
path the pwsh tests drive and the lab measured with (MEASURED-1.5, "Stage
7 on BUILD1 and BUILD2", the helper and K stand-ins of the lab).  The
bootstrap wrote K to ``C:\\NewtonBuild\\k.hex`` and the helper beside it, so
a server bootstrapped by ``bootstrap.py`` answered no request.

The end-to-end test renders the bootstrap, runs its own key and helper
step under pwsh (the owner's passphrase typed into ``Read-Host``; the two
Windows roots moved under the test's directory, nothing else changed), and
then sends the helper a status request whose token is minted with the K the
Newton host derives from the same passphrase.  The helper answers it only
when it finds K and the device name where the bootstrap wrote them.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any

import pytest

from newton_mcp import approve
from newton_mcp.ad.build import bootstrap, plan
from ops_fixture import OPS  # type: ignore[import-not-found]
from pwsh_path import PWSH

HELPER = Path(bootstrap.__file__).with_name("helper") / "build.ps1"

#: The passphrase of the test (synthetic).
PASSPHRASE = "a passphrase of the bootstrap test"

#: The clock of the test: 2026-11-15T00:00:00Z.
NOW = 1794700800

PLAN_INPUTS: dict[str, Any] = {
    "domain": {
        "dns_name": "ad-build.test",
        "netbios": "ADBUILD",
        "functional_level": "Win2025",
        "site": "Default-First-Site-Name",
        "ou_tree": ["IT/Servers"],
        "groups": ["IT Admins"],
        "owner_admin": "owner-admin",
    },
    "servers": [
        {
            "device": "build1",
            "role": "dc1",
            "hostname": "DC1",
            "ip": "192.0.2.11",
            "prefix": 24,
            "gateway": "192.0.2.1",
            "forwarders": ["192.0.2.53"],
            "checkpoint": "hyperv",
        }
    ],
    "baseline": {"version": "2026.11", "options": {"administrator": "random-password"}},
    "accepted_findings": [],
    "ops": dict(OPS),
}


def _pwsh() -> str:
    if not PWSH.is_file():
        pytest.fail("the gate of AD 1.5 task 8 requires the pwsh tests to run")
    return str(PWSH)


def _helper_constant(name: str) -> str:
    """One single-quoted ``$script:`` constant of the helper's text."""
    text = HELPER.read_text(encoding="utf-8")
    match = re.search(r"^\$script:" + re.escape(name) + r" = '([^']*)'$", text, re.MULTILINE)
    assert match is not None, name
    return match.group(1)


def _the_plan() -> dict[str, Any]:
    return plan.plan_build(copy.deepcopy(PLAN_INPUTS))


def test_the_bootstrap_installs_k_the_device_and_the_helper_under_the_helpers_install_root() -> None:
    root = _helper_constant("DefaultInstallRoot")
    assert bootstrap.INSTALL_ROOT == root
    assert bootstrap.KEY_FILE == root + "\\" + _helper_constant("KeyFileName")
    assert bootstrap.DEVICE_FILE == root + "\\" + _helper_constant("DeviceFileName")
    assert bootstrap.HELPER_FILE == root + "\\build.ps1"
    script = bootstrap.render_bootstrap(_the_plan(), "dc1")
    assert f"-ExecutionPolicy Bypass -File {bootstrap.HELPER_FILE}'" in script
    assert "k.hex" not in script


def test_the_install_root_is_protected_before_k_is_written_in_it() -> None:
    script = bootstrap.render_bootstrap(_the_plan(), "dc1")
    protected = script.index("Protect-NewtonPath -Path $InstallRoot -Inheritance 'ContainerInherit, ObjectInherit'")
    written = script.index("[System.IO.File]::WriteAllText($KeyFile, $keyHex")
    assert protected < written
    for path in ("$KeyFile", "$HelperFile", "$DeviceFile"):
        assert f"Protect-NewtonPath -Path {path} -Inheritance 'None'" in script


def _moved(text: str, roots: dict[str, Path]) -> str:
    """The script with each Windows root moved under the test's directory,
    its paths' backslashes turned to slashes (pwsh on Linux)."""
    for windows, local in roots.items():
        pattern = re.compile(r"'" + re.escape(windows) + r"((?:\\[^'\\]+)*)'")
        text = pattern.sub(lambda m, l=local: "'" + str(l) + m.group(1).replace("\\", "/") + "'", text)
    return text


def _run_bootstrap_key_step(script: str, tmp_path: Path) -> dict[str, Path]:
    return _run_bootstrap_step(script, tmp_path)[0]


def _run_bootstrap_step(script: str, tmp_path: Path) -> tuple[dict[str, Path], str]:
    # The helper's own install root (what it reads), not the bootstrap's
    # constant: the test asks whether the two agree.
    roots = {
        _helper_constant("DefaultInstallRoot"): tmp_path / "programdata-newton-ad-build",
        bootstrap.BUILD_DIR: tmp_path / "newtonbuild",
    }
    # Step 3 makes the build directory; this test runs step 5 alone.
    roots[bootstrap.BUILD_DIR].mkdir()
    header = script.split("Write-Host 'Step 1:")[0]
    step = script[script.index("Write-Host 'Step 5:") : script.index("Write-Host 'Step 6:")]
    program = (
        _moved(header, roots)
        # Linux has no ACLs of Windows: the rule is the bootstrap's own
        # (test_build_bootstrap.py pins it); this test reads the paths.
        + "\nfunction Protect-NewtonPath { param([string]$Path, [string]$Inheritance) }\n"
        + "function Read-Host { param([switch]$AsSecureString, [string]$Prompt) "
        + f"ConvertTo-SecureString -String '{PASSPHRASE}' -AsPlainText -Force }}\n"
        + _moved(step, roots)
    )
    path = tmp_path / "bootstrap-step.ps1"
    path.write_text(program, encoding="utf-8")
    run = subprocess.run(
        [_pwsh(), "-NoProfile", "-NonInteractive", "-File", str(path)],
        capture_output=True, text=True, timeout=180, check=False,
    )
    assert run.returncode == 0, run.stdout + run.stderr
    return roots, run.stdout


def test_the_helper_answers_with_the_k_and_the_device_the_bootstrap_wrote(tmp_path: Path) -> None:
    the_plan = _the_plan()
    script = bootstrap.render_bootstrap(the_plan, "dc1")
    roots = _run_bootstrap_key_step(script, tmp_path)
    install = roots[_helper_constant("DefaultInstallRoot")]
    # The helper the forced command runs is the one that reads that root.
    helper = install / "build.ps1"
    # F8 of the part B review: the helper must be the one the bootstrap
    # installed; the test never puts one there itself.
    assert helper.is_file(), "the bootstrap did not install build.ps1 under the helper's install root"
    assert helper.read_bytes() == HELPER.read_bytes()
    k_hex = approve.derive_k(PASSPHRASE.encode("utf-8"), "build1")
    digest = plan.digest(the_plan)
    request = {
        "run": "e5" * 16,
        "plan": base64.b64encode(plan.canonical_bytes(the_plan)).decode("ascii"),
        "stage": "0",
        "action": "status",
        "token": approve.approval_token(k_hex, digest, NOW - 60, NOW + 3600),
        "nbf": NOW - 60,
        "exp": NOW + 3600,
    }
    run = subprocess.run(
        [_pwsh(), "-NoProfile", "-NonInteractive", "-File", str(helper),
         "-InstallRoot", str(install), "-Now", str(NOW), "-BootTime", "2026-11-15T00:00:00Z"],
        input=json.dumps(request), capture_output=True, text=True, timeout=300, check=False,
    )
    answer = json.loads(run.stdout)
    assert (answer["ok"], answer["status"]) == (True, "pending"), answer
    assert (install / "build.ps1").read_bytes() == HELPER.read_bytes()


# --------------------------------------------------------------------------
# DC1's bootstrap installs the 1.4 write helper of stage 8 (the maintainer's decision of
# 2026-11-19 on the stage 8 transport, DESIGN-1.5 open point 78): Windows
# PowerShell 5.1 under OpenSSH hangs reading stdin past about 70 to 80 KB
# and the write helper is about 182 KB in a request, so no request carries
# it; the helper checks the installed file against the plan at stage 8.
# --------------------------------------------------------------------------


def test_the_bootstrap_installs_the_write_helper_where_the_helper_reads_it() -> None:
    assert bootstrap.WRITE_HELPER_FILE == _helper_constant("DefaultInstallRoot") + "\\" + _helper_constant("WriteHelperFileName")
    script = bootstrap.render_bootstrap(_the_plan(), "dc1")
    assert "Protect-NewtonPath -Path $WriteHelperFile -Inheritance 'None'" in script
    assert f"$WriteHelperFile = '{bootstrap.WRITE_HELPER_FILE}'" in script


def test_dc1s_bootstrap_writes_the_plans_write_helper_under_pwsh(tmp_path: Path) -> None:
    """The file lands at the helper's path with the bytes whose sha256 the
    plan names, and the script prints that sha256 for the owner to compare
    with the one newton-approve prints."""
    from newton_mcp.ad import setupgen_write

    the_plan = _the_plan()
    roots, stdout = _run_bootstrap_step(bootstrap.render_bootstrap(the_plan, "dc1"), tmp_path)
    installed = roots[_helper_constant("DefaultInstallRoot")] / _helper_constant("WriteHelperFileName")
    assert installed.read_bytes() == setupgen_write.WRITE_HELPER_PATH.read_bytes()
    assert hashlib.sha256(installed.read_bytes()).hexdigest() == the_plan["ops"]["write_helper_sha256"]
    assert ("Its sha256 is " + the_plan["ops"]["write_helper_sha256"]) in stdout


def test_dc2s_bootstrap_installs_no_write_helper() -> None:
    inputs = copy.deepcopy(PLAN_INPUTS)
    inputs["servers"].append(dict(inputs["servers"][0], device="build2", role="dc2", hostname="DC2", ip="192.0.2.12"))
    script = bootstrap.render_bootstrap(plan.plan_build(inputs), "dc2")
    assert "s8-write.ps1" not in script and "WriteHelper" not in script
