"""What the real Windows DC found in that build.

The Windows script printed by the earlier build ran (with the
Windows write helper merged in, so ``write.ps1`` was there) as
Administrator on the real Server 2025 PDC
``WSBXDC1.win2.newton.test``, under Windows PowerShell 5.1.  The
account ``newton-ops`` had been deleted first.  The run stopped at the
first delegation grant:

    the ACE <sid>:WP;userAccountControl;user on OU=NewtonOps,... is
    not there after the grant

That refusal is correct behaviour for a read-back that cannot match,
and the read-back could not match: the GUID of the schema was read as
a string of bytes.

The three items below are the ones that run found, and every test
here runs the generated PowerShell against a fake of Active Directory
whose answers are the measured ones.

The helpers of these tests are in ``windows_run.py``: the model of the
domain, the runner under pwsh and the readers of the generated script.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from windows_run import (
    AD_FAKE,
    DOMAIN_DN,
    GUID_USER,
    GUID_USER_ACCOUNT_CONTROL,
    OPS_SID,
    OU,
    PDC_POLICY_PATH,
    delegation_program,
    fake_model,
    powershell_prelude,
    run_program,
    step_text,
)


# ---- the GUID of the schema -------------------------------------------------


def test_the_guid_of_the_schema_is_the_guid_of_the_bytes(
    windows_script: str, tmp_path: Path
) -> None:
    """The schemaIDGUID of the directory is a byte array.

    A string of it is ``104 122 150 191 230 13 208 17 162 133 0 170
    0 48 73 226``, and it never matches the GUID of the rule of an
    object.  The bytes are turned into a GUID, and the GUID is what
    the script keeps.
    """
    program = "\n".join(
        [
            "$ErrorActionPreference = 'Stop'",
            f". '{AD_FAKE}'",
            powershell_prelude(windows_script),
            "$schemaDn = 'CN=Schema,CN=Configuration,' + $DomainDn",
            "$attribute = Get-SchemaGuid $schemaDn 'userAccountControl' 'attributeSchema'",
            f"if ($attribute -ne '{GUID_USER_ACCOUNT_CONTROL}') {{",
            "  Write-Output ('the attribute is: ' + $attribute)",
            "  exit 1",
            "}",
            "$class = Get-SchemaGuid $schemaDn 'user' 'classSchema'",
            f"if ($class -ne '{GUID_USER}') {{",
            "  Write-Output ('the class is: ' + $class)",
            "  exit 1",
            "}",
            "Write-Output 'ok'",
        ]
    )

    result, _ = run_program(program, tmp_path, fake_model())

    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "ok"


def test_the_fake_answers_the_schema_guid_as_a_byte_array(
    tmp_path: Path,
) -> None:
    """The fake answers the schemaIDGUID as a byte array.

    The fake is the measured one: the directory answers the sixteen
    bytes of the GUID, in the order of .NET, and a script that reads
    them as a string gets a string of numbers.
    """
    program = "\n".join(
        [
            "$ErrorActionPreference = 'Stop'",
            f". '{AD_FAKE}'",
            "$search = 'CN=Schema,CN=Configuration," + DOMAIN_DN + "'",
            "$object = @(Get-ADObject -SearchBase $search -SearchScope Subtree"
            " -LDAPFilter '(lDAPDisplayName=userAccountControl)'"
            " -Properties schemaIDGUID, objectClass)[0]",
            "if (-not ($object.schemaIDGUID -is [byte[]])) {",
            "  Write-Output ('the type is: ' + $object.schemaIDGUID.GetType().FullName)",
            "  exit 1",
            "}",
            "if ($object.schemaIDGUID.Length -ne 16) {",
            "  Write-Output 'it is not sixteen bytes'",
            "  exit 1",
            "}",
            f"if (([guid][byte[]]$object.schemaIDGUID).ToString() -ne '{GUID_USER_ACCOUNT_CONTROL}') {{",
            "  Write-Output ('the guid is: ' + ([guid][byte[]]$object.schemaIDGUID).ToString())",
            "  exit 1",
            "}",
            "Write-Output 'ok'",
        ]
    )

    result, _ = run_program(program, tmp_path, fake_model())

    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "ok"


def test_the_grants_are_read_back_after_they_are_made(
    windows_script: str, tmp_path: Path
) -> None:
    """Every grant is read back, and the read-back matches.

    This is the measured run: it stopped at the first grant,
    because the GUID of the rule of the object and the GUID the
    script asked for were never the same string.
    """
    result, recorded = run_program(
        delegation_program(windows_script), tmp_path, fake_model()
    )

    assert result.returncode == 0, result.stdout + result.stderr
    # Thirteen aces on the location since the reset-password grant, and one on the head.
    assert len(recorded["dsacls"]) == 14
    rules = recorded["rules"][OU]
    assert len(rules) == 13
    assert rules[0]["objectType"] == GUID_USER_ACCOUNT_CONTROL
    assert rules[0]["inheritedObjectType"] == GUID_USER


# ---- the output of dsacls ---------------------------------------------------


def test_the_output_of_dsacls_is_not_printed(
    windows_script: str, tmp_path: Path
) -> None:
    """The output of dsacls is captured, and it is never printed.

    Every ``dsacls`` prints the WHOLE access control list of the object
    it is given: the measured run printed about 5400 lines.  The
    script keeps the one-line report of every grant and nothing else.
    """
    result, recorded = run_program(
        delegation_program(windows_script), tmp_path, fake_model()
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "(A;;" not in result.stdout
    # Thirteen grants on the location since the reset-password grant, and one on the head.
    assert result.stdout.count("is added") == 14


def test_the_output_of_dsacls_is_printed_when_the_call_failed(
    windows_script: str, tmp_path: Path
) -> None:
    """The output of dsacls is printed when the call failed.

    The reason of a refusal is the one thing the owner has to read, so
    it is printed with the refusal and not before it.
    """
    result, _ = run_program(
        delegation_program(windows_script), tmp_path, fake_model(dsaclsExit=87)
    )

    assert result.returncode != 0
    assert "dsacls said" in result.stdout
    assert "the access control list of the object could not be read" in result.stdout


# ---- the objects that were printed -------------------------------------------


def _policy_program(windows_script: str, tmp_path: Path) -> tuple[str, dict[str, Any]]:
    """The program that runs the step 6 against the fake, and its model."""
    gpo = tmp_path / "gpo"
    gpo.mkdir()
    (gpo / "GPT.INI").write_text("[General]\r\nVersion=7\r\n", encoding="ascii")
    machine = gpo / "Machine" / "Microsoft" / "Windows NT" / "SecEdit"
    machine.mkdir(parents=True)
    (machine / "GptTmpl.inf").write_bytes(
        b"\xff\xfe[Unicode]\x00\r\x00\n\x00U\x00n\x00i\x00c\x00o\x00d\x00e\x00=\x00y\x00e\x00s\x00"
    )
    model = fake_model(
        objects=[
            {
                "DistinguishedName": (
                    "CN={6AC1786C-016F-11D2-945F-00C04fB984F9},CN=Policies,"
                    f"CN=System,{DOMAIN_DN}"
                ),
                "objectClass": ["groupPolicyContainer"],
                "versionNumber": 3,
                "gPCFileSysPath": PDC_POLICY_PATH,
            }
        ],
        policyDir=str(gpo),
        userRights=(
            "[Unicode]\nUnicode=yes\n[Privilege Rights]\n"
            "SeBatchLogonRight = newton-ops,*S-1-5-32-544\n"
        ),
    )
    program = "\n".join(
        [
            "$ErrorActionPreference = 'Stop'",
            f". '{AD_FAKE}'",
            powershell_prelude(windows_script),
            "function Resolve-NewtonAccountSid { param([string]$Name) return '"
            + OPS_SID
            + "' }",
            "$isPdc = $true",
            f"$opsSid = '{OPS_SID}'",
            f"$GpoBackupRoot = '{tmp_path / 'gpo-backup'}'",
            # The backup of the policy is made by the step 0, and this
            # program runs the step 6 alone.
            "$backupDir = Join-Path $GpoBackupRoot '20261109-000000'",
            f"$env:TEMP = '{tmp_path}'",
            step_text(windows_script, 6),
            "@{ calls = @($script:FakeCalls) } | ConvertTo-Json -Depth 8 |"
            " Set-Content -LiteralPath $env:NEWTON_FAKE_OUT -Encoding utf8",
        ]
    )
    return program, model


def test_the_backup_of_the_policy_prints_no_object(
    windows_script: str, tmp_path: Path
) -> None:
    """The result of Backup-GPO goes to Out-Null.

    The real cmdlet answers the policy it backed up, and the object was
    printed by the measured run.
    """
    program, model = _policy_program(windows_script, tmp_path)

    result, _ = run_program(program, tmp_path, model)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "DisplayName" not in result.stdout


def test_the_verify_prints_one_line(
    windows_script: str, tmp_path: Path
) -> None:
    """The verify of the right prints ONE line.

    The measured run printed the match object of Select-String
    (``Line : ...``, ``Pattern : ...``).
    """
    program, model = _policy_program(windows_script, tmp_path)

    result, _ = run_program(program, tmp_path, model)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "SeBatchLogonRight holds newton-ops (verified by secedit)" in result.stdout
    assert "Line :" not in result.stdout
    assert "Pattern :" not in result.stdout


#: The commands of the generated script that write nothing, so that they
#: never reach the host.  Every one of them is here for a reason.
SILENT_COMMANDS = frozenset(
    {
        "Add-ADGroupMember",  # no -PassThru
        "Copy-Item",  # no -PassThru
        "Remove-Item",  # no -PassThru
        "Set-Acl",  # the cmdlet writes nothing
        "Set-ADObject",  # no -PassThru
        "Set-NewtonInstallAcl",  # the function of the script, it returns nothing
        "Set-StrictMode",  # the cmdlet writes nothing
        "Start-Sleep",  # the cmdlet writes nothing
        "Test-NoReplicationRight",  # the function of the script, it returns nothing
        "Test-NoResetPasswordRight",  # the function of the script, it returns nothing
        "Test-NoResetPasswordRule",  # the function of the script, it returns nothing
        "Unregister-ScheduledTask",  # no -PassThru
    }
)

#: The .NET methods of the script that write nothing.
VOID_DOTNET_METHODS = re.compile(
    r"^\[[^\]]+\]::(?:WriteAllText|WriteAllBytes|WriteAllLines|Clear|ZeroFreeBSTR)\("
)

#: The words that open a statement that is not a command.
CONTROL_WORDS = re.compile(
    r"^(?:if|else|elseif|foreach|for|while|do|switch|function|filter|try|catch"
    r"|finally|param|begin|process|end|return|throw|break|continue|exit|in)\b",
    re.IGNORECASE,
)


def _strip_comment(line: str) -> str:
    """The line without its comment."""
    kept: list[str] = []
    quote: str | None = None
    for character in line:
        if quote is not None:
            kept.append(character)
            if character == quote:
                quote = None
            continue
        if character in "'\"":
            quote = character
            kept.append(character)
            continue
        if character == "#":
            break
        kept.append(character)
    return "".join(kept)


def _open_parentheses(text: str) -> int:
    """The number of parentheses that are open at the end of the text."""
    depth = 0
    quote: str | None = None
    for character in text:
        if quote is not None:
            if character == quote:
                quote = None
            continue
        if character in "'\"":
            quote = character
            continue
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
    return depth


def _statements(script: str) -> list[str]:
    """The statements of the generated PowerShell, one per statement.

    The comments are removed, the lines that continue a statement with
    a backtick are joined, and the lines that are the inside of an
    array are part of the statement that opens it.
    """
    statements: list[str] = []
    current = ""
    for raw in script.splitlines():
        line = _strip_comment(raw).strip()
        if not line:
            continue
        if current:
            current += " " + line
        else:
            current = line
        if current.endswith("`"):
            current = current[:-1].strip()
            continue
        if _open_parentheses(current) > 0:
            continue
        statements.append(current)
        current = ""
    if current:
        statements.append(current)
    return statements


def _pipeline(statement: str) -> list[str]:
    """The segments of the pipeline of a statement.

    A pipe that is inside a parenthesis is not a pipe of the pipeline.
    """
    segments: list[str] = []
    current: list[str] = []
    depth = 0
    quote: str | None = None
    for character in statement:
        if quote is not None:
            current.append(character)
            if character == quote:
                quote = None
            continue
        if character in "'\"":
            quote = character
            current.append(character)
            continue
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
        if character == "|" and depth == 0:
            segments.append("".join(current))
            current = []
            continue
        current.append(character)
    segments.append("".join(current))
    return segments


def _command_of(segment: str) -> str:
    """The name of the command of a segment of a pipeline."""
    text = segment.strip()
    if not text:
        return ""
    if text.startswith("&"):
        return "&"
    return text.split()[0].strip("'\"")


def _is_a_string(argument: str) -> bool:
    """True when the argument of a Write-Host is a string."""
    text = argument.strip()
    if not text:
        return False
    if text[0] in "'\"":
        return True
    if text.startswith("(") and text.endswith(")"):
        inner = text[1:-1]
        if "'" in inner or '"' in inner:
            return True
        return "-join" in inner or " -f " in inner
    return False


def test_every_line_that_reaches_the_host_is_a_report(
    windows_script: str,
) -> None:
    """Every pipeline that ends at the host is a report, or nothing.

    A pipeline that ends at the host is either a ``Write-Host`` of a
    string, or it goes to ``Out-Null``.  A command that writes nothing
    does not end at the host, and the ones that do are listed in
    ``SILENT_COMMANDS``.  Nothing else may print: a run that prints an
    object prints the internals of the directory, and the owner has to
    read the report and nothing else.
    """
    offenders: list[str] = []
    for statement in _statements(windows_script):
        text = statement.strip()
        if not text:
            continue
        if text.startswith(("$", "}", "{", ")", "]", "@", "'", '"', "(")):
            # An assignment, a block, or the inside of an array.
            continue
        if CONTROL_WORDS.match(text):
            continue
        if text.startswith("["):
            if not VOID_DOTNET_METHODS.match(text):
                offenders.append(text)
            continue
        segments = _pipeline(text)
        command = _command_of(segments[-1])
        if command == "Write-Host":
            argument = segments[-1].strip()[len("Write-Host") :].strip()
            if not _is_a_string(argument):
                offenders.append(text)
            continue
        if command == "Out-Null":
            continue
        if command in SILENT_COMMANDS:
            continue
        offenders.append(text)

    assert offenders == []
