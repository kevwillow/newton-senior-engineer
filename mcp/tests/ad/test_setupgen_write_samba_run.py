"""Regressions of the Samba write setup: run the generated script against measured bytes."""

from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
import textwrap
from pathlib import Path

import pytest

from newton_mcp.ad import setupgen_write as write
from pwsh_path import PWSH
from tests.ad.fixtures import samba_setup_measured as measured


DOMAIN = "lab2.newton.test"
DOMAIN_DN = "DC=lab2,DC=newton,DC=test"
SCHEMA_DN = "CN=Schema,CN=Configuration," + DOMAIN_DN
OU = "OU=Users," + DOMAIN_DN
PUBLIC_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

#: The objectGUID of the domain head, the way ldbsearch answers it on
#: Samba: the GUID is a plain string value in the LDIF.
DOMAIN_HEAD_GUID = "cf9619ff-8b86-d011-b42d-00c04fc964ff"
DOMAIN_HEAD_GUID_LDIF = (
    "# record 1\n"
    "dn: " + DOMAIN_DN + "\n"
    "objectGUID: " + DOMAIN_HEAD_GUID + "\n"
).encode("ascii")

#: The names of ``samba.dcerpc.security`` that the setup may use.  They
#: were measured on the DC of the lab on 2026-11-09, Samba 4.22.11.  A
#: name that is not in this set does not exist: the module of Samba has
#: no such attribute.
MEASURED_SECURITY_NAMES = frozenset(
    {
        "descriptor",
        "dom_sid",
        "SEC_ACE_OBJECT_TYPE_PRESENT",
        "SEC_ACE_INHERITED_OBJECT_TYPE_PRESENT",
        "SEC_ACE_TYPE_ACCESS_ALLOWED_OBJECT",
        "SEC_ADS_CONTROL_ACCESS",
    }
)


@pytest.fixture
def helpers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """The stub write helpers of this build.

    The write helpers are built on other branches and the Windows one is
    not in this tree at all, so the tests point the path constants of
    the module at small stub files.
    """
    stub = tmp_path / "helpers"
    stub.mkdir()
    windows = stub / "write.ps1"
    windows.write_text("# the stub of the Windows write helper\n", encoding="utf-8")
    samba = stub / "newton-ad-samba-write"
    samba.write_text("#!/bin/sh\n# the stub of the Samba write helper\n", encoding="utf-8")
    monkeypatch.setattr(write, "WRITE_HELPER_PATH", windows)
    monkeypatch.setattr(write, "SAMBA_WRITE_HELPER_PATH", samba)
    return stub


@pytest.fixture
def samba_script(helpers: Path) -> str:
    """The real generated setup, with the package's real helper payload."""
    return write.samba_write_script(
        domain=DOMAIN,
        pubkey=PUBLIC_KEY,
        device="sdc1",
        host="sdc1.lab2.newton.test",
        ous=[OU],
    )


def _embedded_python(script: str) -> str:
    marker = 'cat > "${WORK_DIR}/ad_write_setup.py"'
    lines = script.splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith(marker)) + 1
    end = next(i for i in range(start, len(lines)) if lines[i] == "NEWTON_AD_PY_EOF")
    return "\n".join(lines[start:end]) + "\n"


def _prechecks(script: str) -> str:
    """The generated shell through step 0, before the first possible write."""
    marker = 'echo "Step 1: the newton-ops account"'
    return script[: script.index(marker)]


def _step_account(script: str) -> str:
    """The generated shell through step 1, the check of the rights.

    The check of the replication rights is the last thing of step 1, so
    the block ends right before the delegation.
    """
    marker = 'echo "Step 2: the delegation"'
    return script[: script.index(marker)]


def _function(script: str, name: str) -> str:
    lines = script.splitlines()
    start = next(i for i, line in enumerate(lines) if line == f"{name}() {{")
    end = next(i for i in range(start + 1, len(lines)) if lines[i] == "}")
    return "\n".join(lines[start : end + 1])


def _write_executable(path: Path, source: str) -> None:
    path.write_text(source, encoding="utf-8")
    path.chmod(0o755)


@pytest.fixture
def fake_commands(tmp_path: Path) -> tuple[Path, Path]:
    """Fake Samba commands whose stdout is the measured DC output."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "commands.jsonl"

    ldb = f'''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path

argv = sys.argv[1:]
with Path(os.environ["FAKE_COMMAND_LOG"]).open("a", encoding="utf-8") as stream:
    stream.write(json.dumps(["ldbsearch"] + argv) + "\\n")

def out(value):
    sys.stdout.buffer.write(value)
    raise SystemExit(0)

base = argv[argv.index("-b") + 1] if "-b" in argv else None
filter_text = next((one for one in argv if one.startswith("(")), "")
attribute = argv[-1] if argv else ""
if base is None and "--scope=base" in argv:
    out(b"dn: DC=lab2,DC=newton,DC=test\\n")
if base == "" and attribute == "dsServiceName":
    out({measured.ROOT_DSE!r})
if base == {DOMAIN_DN!r} and attribute == "fSMORoleOwner":
    owner = os.environ.get("FAKE_ROLE_OWNER")
    if owner:
        out(("fSMORoleOwner: " + owner + "\\n").encode("ascii"))
    out({measured.FSMO_ROLE_OWNER!r})
if base == {DOMAIN_DN!r} and attribute == "objectGUID":
    mode = os.environ.get("FAKE_DOMAIN_GUID", "lower")
    if mode == "upper":
        out(("objectGUID: " + {DOMAIN_HEAD_GUID.upper()!r} + "\\n").encode("ascii"))
    if mode == "rubbish":
        out(b"objectGUID: not-a-guid\\n")
    out({DOMAIN_HEAD_GUID_LDIF!r})
if attribute == "dn":
    out(("dn: " + (base or "") + "\\n").encode("ascii"))
if attribute == "objectSid":
    out({measured.OBJECT_SID!r})
if attribute == "tokenGroups":
    mode = os.environ.get("FAKE_TOKEN_GROUPS", "present")
    if mode == "error":
        raise SystemExit(7)
    if mode == "empty":
        out(b"")
    out({measured.TOKEN_GROUPS!r})
if base and base.startswith("CN=Extended-Rights,") and attribute.lower() == "rightsguid":
    value = {measured.EXTENDED_RIGHTS!r}
    if os.environ.get("FAKE_RIGHTS_COUNT") == "2":
        value = b"\\n\\n".join(value.split(b"\\n\\n")[:2]) + b"\\n"
    out(value)
if attribute == "schemaIDGUID" and filter_text == "(lDAPDisplayName=user)":
    out({measured.SCHEMA_USER!r})
if attribute == "schemaIDGUID" and filter_text == "(lDAPDisplayName=userAccountControl)":
    out({measured.SCHEMA_UAC!r})
out(b"")
'''
    _write_executable(bindir / "ldbsearch", ldb)

    samba = f'''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path

argv = sys.argv[1:]
with Path(os.environ["FAKE_COMMAND_LOG"]).open("a", encoding="utf-8") as stream:
    stream.write(json.dumps(["samba-tool"] + argv) + "\\n")
if argv[:2] == ["domain", "info"]:
    sys.stdout.buffer.write({measured.DOMAIN_INFO!r})
elif argv and argv[0] == "testparm":
    sys.stdout.buffer.write({measured.TESTPARM_REALM!r})
elif argv[:2] == ["user", "show"]:
    print("dn: CN=newton-ops,CN=Users,{DOMAIN_DN}")
    print("userAccountControl: 1049088")
elif argv[:2] == ["dsacl", "set"]:
    state = Path(os.environ["FAKE_DSACL_STATE"])
    state.write_text(argv[argv.index("--sddl") + 1], encoding="ascii")
    print("old descriptor for object:")
    print("O:SYG:SYD:")
    print("new descriptor for object:")
    print("O:SYG:SYD:" + state.read_text(encoding="ascii"))
elif argv[:2] == ["dsacl", "get"]:
    mode = os.environ.get("FAKE_DSACL_MODE", "present")
    if mode == "present":
        sys.stdout.buffer.write({measured.PRESENT_OBJECT_ACE!r})
    elif mode == "du-replication":
        sys.stdout.buffer.write({measured.DU_REPLICATION_ACE!r})
    elif mode == "du-all":
        sys.stdout.buffer.write({measured.DU_ALL_EXTENDED_ACE!r})
    elif mode == "widened":
        state = Path(os.environ["FAKE_DSACL_STATE"])
        if state.exists():
            sys.stdout.buffer.write({measured.WIDENED_ACE!r})
        else:
            print("descriptor for object:")
            print("O:SYG:SYD:")
    elif mode == "add-exact":
        state = Path(os.environ["FAKE_DSACL_STATE"])
        print("descriptor for object:")
        print("O:SYG:SYD:" + (state.read_text(encoding="ascii") if state.exists() else ""))
else:
    raise SystemExit(2)
'''
    _write_executable(bindir / "samba-tool", samba)
    _write_executable(bindir / "id", "#!/bin/sh\nprintf '0\\n'\n")
    return bindir, log


@pytest.fixture
def fake_security(tmp_path: Path) -> Path:
    """Measured surface of samba.dcerpc.security, for the offline test host.

    The module exposes ONLY the names that were measured on the DC: the
    two functions and the four constants.  The name that the setup used
    before the fix, ``access_allowed_object``, does not exist in Samba and
    is not here either.
    """
    root = tmp_path / "python"
    package = root / "samba" / "dcerpc"
    package.mkdir(parents=True)
    (root / "samba" / "__init__.py").write_text("", encoding="utf-8")
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "security.py").write_text(
        textwrap.dedent(
            '''
            SEC_ACE_OBJECT_TYPE_PRESENT = 1
            SEC_ACE_INHERITED_OBJECT_TYPE_PRESENT = 2
            SEC_ACE_TYPE_ACCESS_ALLOWED_OBJECT = 5
            SEC_ADS_CONTROL_ACCESS = 256

            def dom_sid(value):
                return value

            class _Object:
                def __init__(self, object_type, inherited_type):
                    self.flags = (
                        (SEC_ACE_OBJECT_TYPE_PRESENT if object_type else 0)
                        | (
                            SEC_ACE_INHERITED_OBJECT_TYPE_PRESENT
                            if inherited_type
                            else 0
                        )
                    )
                    self.type = object_type
                    self.inherited_type = inherited_type

            class _Ace:
                def __init__(self, fields, domain_sid):
                    aliases = {
                        "LG": domain_sid + "-501", "DU": domain_sid + "-513",
                        "DD": domain_sid + "-516", "BA": "S-1-5-32-544", "ED": "S-1-5-9",
                    }
                    masks = {"WP": 0x20, "CR": 0x100, "CCDC": 3}
                    if len(fields) < 6:
                        raise ValueError("Unable to parse SDDL")
                    if len(fields) > 6:
                        # Samba reads a trailing section on a callback
                        # or a resource ACE only, and an ACE of type A
                        # or OA is neither.
                        raise ValueError(
                            "ACE has trailing section but is not a "
                            "callback or resource ACE"
                        )
                    self.type = {
                        "A": 0,
                        "OA": SEC_ACE_TYPE_ACCESS_ALLOWED_OBJECT,
                    }[fields[0]]
                    self.flags = (1 if "OI" in fields[1] else 0) | (2 if "CI" in fields[1] else 0)
                    self.access_mask = masks.get(fields[2], int(fields[2], 16) if fields[2].startswith("0x") else 0)
                    object_type = fields[3]
                    inherited_type = fields[4]
                    trustee = fields[5]
                    if self.type == SEC_ACE_TYPE_ACCESS_ALLOWED_OBJECT:
                        self.object = _Object(object_type, inherited_type)
                    else:
                        # A plain ACE carries no object at all.
                        self.object = None
                    self.trustee = aliases.get(trustee, trustee)

            class descriptor:
                @classmethod
                def from_sddl(cls, sddl, domain_sid):
                    value = cls()
                    value.dacl = type("Dacl", (), {})()
                    aces = []
                    rest = sddl
                    while True:
                        start = rest.find("(")
                        if start < 0:
                            break
                        end = rest.find(")", start)
                        if end < 0:
                            break
                        aces.append(_Ace(rest[start + 1:end].split(";"), domain_sid))
                        rest = rest[end + 1:]
                    value.dacl.aces = aces
                    return value
            '''
        ),
        encoding="utf-8",
    )
    return root


def _env(
    tmp_path: Path,
    bindir: Path,
    log: Path,
    fake_security: Path | None = None,
    **extra: str,
) -> dict[str, str]:
    env = {
        "PATH": f"{bindir}:/usr/bin:/bin",
        "HOME": str(tmp_path),
        "FAKE_COMMAND_LOG": str(log),
        "FAKE_DSACL_STATE": str(tmp_path / "dsacl-state"),
    }
    if fake_security is not None:
        env["PYTHONPATH"] = str(fake_security)
    env.update(extra)
    return env


def _run_embedded(
    tmp_path: Path,
    script: str,
    bindir: Path,
    log: Path,
    fake_security: Path,
    program: str,
    **extra: str,
) -> subprocess.CompletedProcess[str]:
    helper = tmp_path / "ad_write_setup.py"
    helper.write_text(_embedded_python(script), encoding="utf-8")
    wrapper = tmp_path / "run_helper.py"
    wrapper.write_text(
        "import runpy\nns = runpy.run_path(" + repr(str(helper)) + ", run_name='embedded')\n" + program,
        encoding="utf-8",
    )
    return subprocess.run(
        ["/usr/bin/python3", str(wrapper)],
        capture_output=True,
        text=True,
        check=False,
        env=_env(tmp_path, bindir, log, fake_security, **extra),
    )


def _commands(log: Path) -> list[list[str]]:
    return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]


def test_prechecks_use_testparm_and_the_root_dse(
    tmp_path: Path, samba_script: str, fake_commands: tuple[Path, Path]
) -> None:
    bindir, log = fake_commands
    path = tmp_path / "prechecks.sh"
    path.write_text(_prechecks(samba_script), encoding="utf-8")

    result = subprocess.run(
        ["/bin/bash", str(path)],
        capture_output=True,
        text=True,
        check=False,
        env=_env(tmp_path, bindir, log),
    )

    assert result.returncode == 0, result.stderr
    assert "This host holds the PDC emulator role" in result.stdout
    calls = _commands(log)
    assert ["samba-tool", "testparm", "--parameter-name=realm", "--suppress-prompt"] in calls
    assert any(
        call[0] == "ldbsearch"
        and call[call.index("-b") + 1] == ""
        and "(objectClass=*)" in call
        and call[-1] == "dsServiceName"
        for call in calls
    )


# ---- the warning of a controller that names itself ---------------------------


#: The role owner of the domain when this controller does not hold the
#: PDC emulator role: another controller of the domain holds it.
OTHER_ROLE_OWNER = (
    "CN=NTDS Settings,CN=SDC2,CN=Servers,CN=Default-First-Site-Name,"
    "CN=Sites,CN=Configuration,DC=lab2,DC=newton,DC=test"
)

#: The head of the warning the setup prints.
WARNING_HEAD = "WARNING: this DC does not hold the PDC emulator role"


def _prechecks_run(
    tmp_path: Path,
    bindir: Path,
    log: Path,
    script: str,
    **extra: str,
) -> subprocess.CompletedProcess[str]:
    """The pre-checks of the generated script, against the fake."""
    path = tmp_path / "prechecks.sh"
    path.write_text(_prechecks(script), encoding="utf-8")

    return subprocess.run(
        ["/bin/bash", str(path)],
        capture_output=True,
        text=True,
        check=False,
        env=_env(tmp_path, bindir, log, **extra),
    )


def test_a_non_pdc_that_names_itself_is_warned(
    tmp_path: Path, samba_script: str, fake_commands: tuple[Path, Path]
) -> None:
    """A controller that does not hold the role and names itself is warned.

    The entry of a controller that names itself is a second device
    standing for the domain: the loader of the inventory refuses it
    when another DC of the domain has an entry too.  The setup warns
    the owner before that happens.
    """
    bindir, log = fake_commands

    result = _prechecks_run(
        tmp_path, bindir, log, samba_script, FAKE_ROLE_OWNER=OTHER_ROLE_OWNER
    )

    assert result.returncode == 0, result.stderr
    assert "This host does not hold the PDC emulator role" in result.stdout
    assert WARNING_HEAD in result.stdout


def test_a_non_pdc_that_names_another_device_is_not_warned(
    tmp_path: Path, samba_script: str, fake_commands: tuple[Path, Path]
) -> None:
    """A controller that names the device of the domain is not warned.

    The entry of a controller that does not hold the role names the
    device that stands for the domain: that is the way it is set up,
    and there is nothing to warn about.
    """
    bindir, log = fake_commands
    script = write.samba_write_script(
        domain=DOMAIN,
        pubkey=PUBLIC_KEY,
        device="sdc1",
        host="sdc1.lab2.newton.test",
        ous=[OU],
        domain_device="sdc-pdc",
    )

    result = _prechecks_run(
        tmp_path, bindir, log, script, FAKE_ROLE_OWNER=OTHER_ROLE_OWNER
    )

    assert result.returncode == 0, result.stderr
    assert WARNING_HEAD not in result.stdout


def test_a_pdc_that_names_itself_is_not_warned(
    tmp_path: Path, samba_script: str, fake_commands: tuple[Path, Path]
) -> None:
    """The controller that holds the role names itself and is not warned.

    The entry of the PDC emulator stands for the domain: it is the one
    device of the domain, and there is nothing to warn about.
    """
    bindir, log = fake_commands

    result = _prechecks_run(tmp_path, bindir, log, samba_script)

    assert result.returncode == 0, result.stderr
    assert "This host holds the PDC emulator role" in result.stdout
    assert WARNING_HEAD not in result.stdout


def test_ldif_value_unfolds_every_setup_read(
    tmp_path: Path, samba_script: str, fake_commands: tuple[Path, Path]
) -> None:
    bindir, log = fake_commands
    function = _function(samba_script, "ldif_value")
    command = textwrap.dedent(
        f'''\
        set -eu
        {function}
        ldbsearch -H sam.ldb -b '' --scope=base '(objectClass=*)' dsServiceName | ldif_value dsServiceName
        ldbsearch -H sam.ldb -b '{DOMAIN_DN}' --scope=base '(objectClass=domainDNS)' fSMORoleOwner | ldif_value fSMORoleOwner
        ldbsearch -H sam.ldb -b 'CN=newton-ops,CN=Users,{DOMAIN_DN}' --scope=base '(objectClass=*)' objectSid | ldif_value objectSid
        ldbsearch -H sam.ldb -b 'CN=newton-ops,CN=Users,{DOMAIN_DN}' --scope=base '(objectClass=*)' tokenGroups | ldif_value tokenGroups
        '''
    )
    result = subprocess.run(
        ["/bin/bash", "-c", command],
        capture_output=True,
        text=True,
        check=False,
        env=_env(tmp_path, bindir, log),
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [
        "CN=NTDS Settings,CN=SDC1,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=lab2,DC=newton,DC=test",
        "CN=NTDS Settings,CN=SDC1,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=lab2,DC=newton,DC=test",
        measured.OPS_SID,
        measured.DOMAIN_USERS_SID,
        measured.DOMAIN_SID + "-515",
    ]
    for attribute in ("dsServiceName", "fSMORoleOwner", "objectSid", "tokenGroups"):
        assert f"ldif_value {attribute}" in samba_script
        assert f"s/^{{attribute}}: " not in samba_script


def test_schema_guid_uses_the_real_attribute_and_filter(
    tmp_path: Path,
    samba_script: str,
    fake_commands: tuple[Path, Path],
    fake_security: Path,
) -> None:
    bindir, log = fake_commands
    result = _run_embedded(
        tmp_path,
        samba_script,
        bindir,
        log,
        fake_security,
        "print(ns['class_guid'](" + repr(SCHEMA_DN) + ", 'sam.ldb', 'user'))\n"
        "print(ns['attribute_guid'](" + repr(SCHEMA_DN) + ", 'sam.ldb', 'userAccountControl'))\n",
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [measured.USER_CLASS_GUID, measured.UAC_ATTRIBUTE_GUID]
    assert any("(lDAPDisplayName=userAccountControl)" in call for call in _commands(log))


def test_every_guid_ace_is_object_specific(
    tmp_path: Path,
    samba_script: str,
    fake_commands: tuple[Path, Path],
    fake_security: Path,
) -> None:
    bindir, log = fake_commands
    program = textwrap.dedent(
        f'''\
        cases = (
            (0x20, {measured.UAC_ATTRIBUTE_GUID!r}, {measured.USER_CLASS_GUID!r}),
            (0x01, {measured.USER_CLASS_GUID!r}, ''),
            (0x20, '', ''),
        )
        for mask, object_type, inherited in cases:
            print(ns['ace']({measured.OPS_SID!r}, mask, object_type, inherited, 'CI'))
        '''
    )
    result = _run_embedded(tmp_path, samba_script, bindir, log, fake_security, program)

    assert result.returncode == 0, result.stderr
    for line in result.stdout.splitlines():
        fields = line.strip("()").split(";")
        assert (fields[0] == "OA") == bool(fields[3] or fields[4])


def test_a_wider_readback_stops_the_grant(
    tmp_path: Path,
    samba_script: str,
    fake_commands: tuple[Path, Path],
    fake_security: Path,
) -> None:
    bindir, log = fake_commands
    wanted = (
        f"(OA;CI;0x00000020;{measured.UAC_ATTRIBUTE_GUID};"
        f"{measured.USER_CLASS_GUID};{measured.OPS_SID})"
    )
    program = (
        "sddl = ns['current_sddl'](" + repr(OU) + ")\n"
        "ns['grant'](sddl, " + repr(OU) + ", " + repr(wanted) + ", 'write uac')\n"
    )
    result = _run_embedded(
        tmp_path,
        samba_script,
        bindir,
        log,
        fake_security,
        program,
        FAKE_DSACL_MODE="widened",
    )

    assert result.returncode == 1
    assert "did not store the requested ACE" in result.stderr


@pytest.mark.parametrize("mode", ["du-replication", "du-all"])
def test_replication_rights_use_extended_rights_and_aliases(
    tmp_path: Path,
    samba_script: str,
    fake_commands: tuple[Path, Path],
    fake_security: Path,
    mode: str,
) -> None:
    bindir, log = fake_commands
    program = (
        "raise SystemExit(ns['rights']("
        + repr(DOMAIN_DN)
        + ", "
        + repr(SCHEMA_DN)
        + ", 'sam.ldb', "
        + repr(measured.OPS_SID)
        + ", ["
        + repr(measured.DOMAIN_USERS_SID)
        + "]))\n"
    )
    result = _run_embedded(
        tmp_path,
        samba_script,
        bindir,
        log,
        fake_security,
        program,
        FAKE_DSACL_MODE=mode,
    )

    assert result.returncode == 1
    assert "replicates the directory" in result.stderr or "every extended right" in result.stderr
    assert any(
        call[0] == "ldbsearch"
        and call[call.index("-b") + 1] == "CN=Extended-Rights,CN=Configuration," + DOMAIN_DN
        and call[-1].lower() == "rightsguid"
        for call in _commands(log)
    )


def test_missing_replication_rights_is_a_refusal_on_samba(
    tmp_path: Path,
    samba_script: str,
    fake_commands: tuple[Path, Path],
    fake_security: Path,
) -> None:
    bindir, log = fake_commands
    program = (
        "raise SystemExit(ns['rights']("
        + repr(DOMAIN_DN)
        + ", "
        + repr(SCHEMA_DN)
        + ", 'sam.ldb', "
        + repr(measured.OPS_SID)
        + ", []))\n"
    )
    result = _run_embedded(
        tmp_path,
        samba_script,
        bindir,
        log,
        fake_security,
        program,
        FAKE_RIGHTS_COUNT="2",
    )

    assert result.returncode == 2
    assert "the replication rights could not be read from this domain" in result.stderr


def test_missing_replication_rights_is_a_refusal_on_windows(
    tmp_path: Path, samba_script: str
) -> None:
    windows = write.windows_write_script(
        domain="win2.newton.test",
        pubkey=PUBLIC_KEY,
        device="wsbxdc1",
        host="wsbxdc1.win2.newton.test",
        ous=["OU=Users,DC=win2,DC=newton,DC=test"],
    )
    lines = windows.splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith("function Test-NoReplicationRight"))
    depth = 0
    end = start
    for i in range(start, len(lines)):
        depth += lines[i].count("{") - lines[i].count("}")
        if i > start and depth == 0:
            end = i
            break
    function = "\n".join(lines[start : end + 1])
    program = textwrap.dedent(
        f'''\
        $DomainDn = 'DC=win2,DC=newton,DC=test'
        function Get-ADObject {{
            @(
                [pscustomobject]@{{ name = 'DS-Replication-Get-Changes'; rightsGuid = '{measured.GET_CHANGES_GUID}' }},
                [pscustomobject]@{{ name = 'DS-Replication-Get-Changes-All'; rightsGuid = '{measured.GET_CHANGES_ALL_GUID}' }}
            )
        }}
        {function}
        Test-NoReplicationRight '{measured.OPS_SID}' @()
        '''
    )
    path = tmp_path / "missing-rights.ps1"
    path.write_text(program, encoding="utf-8")
    pwsh = PWSH
    if not pwsh.exists():
        pytest.fail("the gate requires the pwsh tests to run")
    result = subprocess.run(
        [str(pwsh), "-NoProfile", "-NonInteractive", "-File", str(path)],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert "the replication rights could not be read from this domain" in result.stderr
    assert "CN=Extended-Rights,CN=Configuration," in function


def test_present_letter_mask_and_alias_is_not_readded(
    tmp_path: Path,
    samba_script: str,
    fake_commands: tuple[Path, Path],
    fake_security: Path,
) -> None:
    bindir, log = fake_commands
    wanted = (
        f"(OA;CI;0x00000020;{measured.UAC_ATTRIBUTE_GUID};"
        f"{measured.USER_CLASS_GUID};{measured.OPS_SID})"
    )
    program = (
        "sddl = ns['current_sddl'](" + repr(OU) + ")\n"
        "ns['grant'](sddl, " + repr(OU) + ", " + repr(wanted) + ", 'write uac')\n"
    )
    result = _run_embedded(tmp_path, samba_script, bindir, log, fake_security, program)

    assert result.returncode == 0, result.stderr
    assert "is present" in result.stdout
    assert not any(call[1:3] == ["dsacl", "set"] for call in _commands(log))


def test_current_sddl_and_set_use_only_descriptor_and_wanted_ace(
    tmp_path: Path,
    samba_script: str,
    fake_commands: tuple[Path, Path],
    fake_security: Path,
) -> None:
    bindir, log = fake_commands
    wanted = (
        f"(OA;CI;0x00000020;{measured.UAC_ATTRIBUTE_GUID};"
        f"{measured.USER_CLASS_GUID};{measured.OPS_SID})"
    )
    program = (
        "sddl = ns['current_sddl'](" + repr(OU) + ")\n"
        "print('CURRENT=' + sddl)\n"
        "ns['grant'](sddl, " + repr(OU) + ", " + repr(wanted) + ", 'write uac')\n"
    )
    result = _run_embedded(
        tmp_path,
        samba_script,
        bindir,
        log,
        fake_security,
        program,
        FAKE_DSACL_MODE="add-exact",
    )

    assert result.returncode == 0, result.stderr
    assert "CURRENT=O:SYG:SYD:" in result.stdout
    set_call = next(call for call in _commands(log) if call[1:3] == ["dsacl", "set"])
    assert set_call[set_call.index("--sddl") + 1] == wanted
    assert "descriptor for" not in set_call[set_call.index("--sddl") + 1]


def test_every_name_of_the_security_module_is_a_measured_name(
    samba_script: str,
) -> None:
    """The helper names only what the module of Samba really has.

    The names of the module were measured on the DC.  A name that is
    not one of them does not exist, and the helper must not use it.
    """
    embedded = _embedded_python(samba_script)
    used = set(re.findall(r"\bsecurity\.([A-Za-z_][A-Za-z0-9_]*)", embedded))

    assert used, "the helper uses no name of the security module"
    assert used <= MEASURED_SECURITY_NAMES


def test_the_fake_module_has_only_the_measured_names(fake_security: Path) -> None:
    """The fake is the module of Samba, and it has the measured names only."""
    path = fake_security / "samba" / "dcerpc" / "security.py"
    spec = importlib.util.spec_from_file_location("measured_security", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    public = {name for name in dir(module) if not name.startswith("_")}

    assert public == set(MEASURED_SECURITY_NAMES)
    assert not hasattr(module, "access_allowed_object")


def test_the_helper_reads_the_measured_names(
    tmp_path: Path,
    samba_script: str,
    fake_commands: tuple[Path, Path],
    fake_security: Path,
) -> None:
    """The helper reads an ACE with the measured names of the module.

    The module of Samba has no ``access_allowed_object``: the flags of
    the object of an ACE are read with the two measured constants.
    """
    bindir, log = fake_commands
    program = textwrap.dedent(
        f'''\
        wanted = ns['ace'](
            {measured.OPS_SID!r},
            0x20,
            {measured.UAC_ATTRIBUTE_GUID!r},
            {measured.USER_CLASS_GUID!r},
            'CI',
        )
        for field in ns['wanted_fields'](wanted, {measured.DOMAIN_SID!r}):
            print(field)
        '''
    )
    result = _run_embedded(tmp_path, samba_script, bindir, log, fake_security, program)

    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [
        "5",
        "2",
        "32",
        measured.UAC_ATTRIBUTE_GUID,
        measured.USER_CLASS_GUID,
        measured.OPS_SID.lower(),
    ]


def test_every_ace_the_helper_builds_has_six_fields(
    tmp_path: Path,
    samba_script: str,
    fake_commands: tuple[Path, Path],
    fake_security: Path,
) -> None:
    """An ACE of the SDDL has six fields.

    The type, the flags, the rights, the object GUID, the inherited
    object GUID and the trustee.  Samba refuses an ACE with a seventh
    field.
    """
    bindir, log = fake_commands
    program = textwrap.dedent(
        f'''\
        cases = (
            (0x20, {measured.UAC_ATTRIBUTE_GUID!r}, {measured.USER_CLASS_GUID!r}, 'CI'),
            (0x01, {measured.USER_CLASS_GUID!r}, '', 'OICI'),
            (0x20, '', '', ''),
        )
        for mask, object_type, inherited, flags in cases:
            print(ns['ace']({measured.OPS_SID!r}, mask, object_type, inherited, flags))
        '''
    )
    result = _run_embedded(tmp_path, samba_script, bindir, log, fake_security, program)

    assert result.returncode == 0, result.stderr
    lines = result.stdout.splitlines()
    assert len(lines) == 3
    for line in lines:
        fields = line.strip().strip("()").split(";")
        assert len(fields) == 6, line
        assert fields[5] == measured.OPS_SID


def test_the_trustee_of_an_ace_is_its_sixth_field(
    tmp_path: Path,
    samba_script: str,
    fake_commands: tuple[Path, Path],
    fake_security: Path,
) -> None:
    """The trustee of the wanted ACE is the sixth field of it."""
    bindir, log = fake_commands
    wanted = (
        f"(OA;CI;0x00000020;{measured.UAC_ATTRIBUTE_GUID};"
        f"{measured.USER_CLASS_GUID};{measured.OPS_SID})"
    )
    program = "print(ns['trustee_of'](" + repr(wanted) + "))\n"
    result = _run_embedded(tmp_path, samba_script, bindir, log, fake_security, program)

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == measured.OPS_SID


def test_the_measured_aces_of_the_dc_have_six_fields() -> None:
    """The ACEs that the DC printed are ACEs of six fields.

    The descriptor of the DC was read back with ``dsacl get``, and the
    ACEs it holds are the ones the helper has to parse.
    """
    for text in (
        measured.PRESENT_OBJECT_ACE,
        measured.DU_REPLICATION_ACE,
        measured.DU_ALL_EXTENDED_ACE,
        measured.WIDENED_ACE,
    ):
        ace = text.decode("ascii").split("(", 1)[1].rstrip(")\n")
        assert len(ace.split(";")) == 6, ace


def test_the_helper_tells_the_two_refusals_apart(
    tmp_path: Path,
    samba_script: str,
    fake_commands: tuple[Path, Path],
    fake_security: Path,
) -> None:
    """The helper exits 1 when it holds a right, and 2 when it cannot check.

    The two refusals are different, and the script has to tell them
    apart: the exit code of the helper is what tells them apart.
    """
    bindir, log = fake_commands
    program = (
        "raise SystemExit(ns['rights']("
        + repr(DOMAIN_DN)
        + ", "
        + repr(SCHEMA_DN)
        + ", 'sam.ldb', "
        + repr(measured.OPS_SID)
        + ", ["
        + repr(measured.DOMAIN_USERS_SID)
        + "]))\n"
    )

    holds = _run_embedded(
        tmp_path,
        samba_script,
        bindir,
        log,
        fake_security,
        program,
        FAKE_DSACL_MODE="du-replication",
    )
    assert holds.returncode == 1, holds.stderr
    assert "newton-ops holds a right that replicates the directory" in holds.stderr

    cannot = _run_embedded(
        tmp_path,
        samba_script,
        bindir,
        log,
        fake_security,
        program,
        FAKE_RIGHTS_COUNT="2",
    )
    assert cannot.returncode == 2, cannot.stderr
    assert "the replication rights could not be read from this domain" in cannot.stderr


@pytest.mark.parametrize(
    ("mode", "rights_count", "expected", "forbidden"),
    [
        (
            "du-replication",
            "",
            "newton-ops holds a right that replicates the directory",
            "could not be checked against the replication rights",
        ),
        (
            "du-replication",
            "2",
            "newton-ops could not be checked against the replication rights of this domain",
            "holds a right that replicates the directory",
        ),
    ],
)
def test_the_script_prints_one_refusal_message(
    tmp_path: Path,
    samba_script: str,
    fake_commands: tuple[Path, Path],
    fake_security: Path,
    mode: str,
    rights_count: str,
    expected: str,
    forbidden: str,
) -> None:
    """The script prints the message of the case, and only that one.

    The script must not tell the operator that the account could not be
    checked when it says that the account holds a right that replicates
    the directory.
    """
    bindir, log = fake_commands
    path = tmp_path / "step1.sh"
    path.write_text(_step_account(samba_script), encoding="utf-8")
    extra = {"FAKE_DSACL_MODE": mode}
    if rights_count:
        extra["FAKE_RIGHTS_COUNT"] = rights_count

    result = subprocess.run(
        ["/bin/bash", str(path)],
        capture_output=True,
        text=True,
        check=False,
        env=_env(tmp_path, bindir, log, fake_security, **extra),
    )

    assert result.returncode != 0
    assert expected in result.stderr
    assert forbidden not in result.stderr


@pytest.mark.parametrize("mode", ["error", "empty"])
def test_samba_refuses_when_token_groups_cannot_be_read(
    tmp_path: Path,
    samba_script: str,
    fake_commands: tuple[Path, Path],
    fake_security: Path,
    mode: str,
) -> None:
    bindir, log = fake_commands
    path = tmp_path / "step1.sh"
    path.write_text(_step_account(samba_script), encoding="utf-8")

    result = subprocess.run(
        ["/bin/bash", str(path)],
        capture_output=True,
        text=True,
        check=False,
        env=_env(
            tmp_path,
            bindir,
            log,
            fake_security,
            FAKE_TOKEN_GROUPS=mode,
        ),
    )

    assert result.returncode == 1
    assert result.stderr.splitlines()[-1] == (
        "the groups of newton-ops could not be read; "
        "nothing after this point was changed"
    )


def test_the_entry_prints_the_guid_of_the_domain_head(
    tmp_path: Path,
    samba_script: str,
    fake_commands: tuple[Path, Path],
) -> None:
    """The pre-checks read the objectGUID of the head and the entry carries it.

    The guid is read with the same ldbsearch of the same base search
    that reads the role owner, and the entry prints it after the
    ``ad_domain`` line: the maq verb targets the head by that guid.
    """
    bindir, log = fake_commands
    step7 = samba_script[samba_script.index('echo "Step 7: the inventory entry"'):]
    path = tmp_path / "entry.sh"
    path.write_text(_prechecks(samba_script) + "\n" + step7, encoding="utf-8")

    result = subprocess.run(
        ["/bin/bash", str(path)],
        capture_output=True,
        text=True,
        check=False,
        env=_env(tmp_path, bindir, log),
    )

    assert result.returncode == 0, result.stderr
    lines = result.stdout.splitlines()
    domain_at = next(
        index for index, line in enumerate(lines)
        if line.startswith("ad_domain = ")
    )
    assert lines[domain_at + 1] == f'ad_domain_guid = "{DOMAIN_HEAD_GUID}"'
    assert any(
        call[0] == "ldbsearch"
        and call[call.index("-b") + 1] == DOMAIN_DN
        and call[-1] == "objectGUID"
        for call in _commands(log)
    )


def test_the_entry_carries_the_guid_in_the_form_the_loader_takes(
    tmp_path: Path,
    samba_script: str,
    fake_commands: tuple[Path, Path],
) -> None:
    """A guid the controller answers in upper case is carried in lower case.

    The loader takes the guid of the domain head in one form only
    (``AD_GUID_RE`` in the server, lower case hex), so the script
    carries the value in that form whatever the case of the answer of
    the directory.
    """
    bindir, log = fake_commands
    step7 = samba_script[samba_script.index('echo "Step 7: the inventory entry"'):]
    path = tmp_path / "entry.sh"
    path.write_text(_prechecks(samba_script) + "\n" + step7, encoding="utf-8")

    result = subprocess.run(
        ["/bin/bash", str(path)],
        capture_output=True,
        text=True,
        check=False,
        env=_env(tmp_path, bindir, log, FAKE_DOMAIN_GUID="upper"),
    )

    assert result.returncode == 0, result.stderr
    assert f'ad_domain_guid = "{DOMAIN_HEAD_GUID}"' in result.stdout


def test_a_domain_guid_that_is_not_a_guid_stops_the_run(
    tmp_path: Path,
    samba_script: str,
    fake_commands: tuple[Path, Path],
) -> None:
    """A value that is not a guid is a refusal and never a broken entry.

    The entry carries the guid of the head of the domain, and the
    loader takes it in one form only.  A value that is not a guid stops
    the run in the pre-checks, where nothing has been changed yet.
    """
    bindir, log = fake_commands
    step7 = samba_script[samba_script.index('echo "Step 7: the inventory entry"'):]
    path = tmp_path / "entry.sh"
    path.write_text(_prechecks(samba_script) + "\n" + step7, encoding="utf-8")

    result = subprocess.run(
        ["/bin/bash", str(path)],
        capture_output=True,
        text=True,
        check=False,
        env=_env(tmp_path, bindir, log, FAKE_DOMAIN_GUID="rubbish"),
    )

    assert result.returncode == 1
    assert result.stderr.splitlines()[-1] == (
        "the objectGUID of the head of the domain is not a guid"
    )
    assert "ad_domain_guid" not in result.stdout
