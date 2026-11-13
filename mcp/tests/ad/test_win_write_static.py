"""Static checks on the Windows write helper.

The helper runs under Windows PowerShell 5.1 on the domain controller, where
pytest never reaches it.  These checks pin the properties that runtime
depends on:

- the code is Windows PowerShell 5.1: no ternary, no null-coalescing
  operator, no ``&&`` or ``||`` pipeline chain, no ``ForEach-Object
  -Parallel`` and no ``ConvertFrom-Json -AsHashtable``;
- it never runs anything dynamic and never hands a password to a cmdlet as
  plain text;
- it never uses the ScheduledTasks cmdlets: the undo task goes through the
  COM API, as it was measured on the lab DC;
- it keeps the shape of the contract: the stdin limit, the scanner, the
  canonical bytes, the LDAP adapter, the transaction store, the task and the
  undo.
"""

from __future__ import annotations

import re
from pathlib import Path


COLLECTOR_DIR = Path(__file__).resolve().parents[2] / "newton_mcp" / "ad" / "collector"
SCRIPT_PATH = COLLECTOR_DIR / "write.ps1"
HARNESS_PATH = Path(__file__).resolve().parent / "win_write_harness.ps1"
FAKE_PATH = Path(__file__).resolve().parent / "win_write_fake.ps1"
SPEC_PATH = Path(__file__).resolve().parents[3] / "docs" / "proposals" / "ad" / "SPEC-1.4-REQUEST.md"
POWERSHELL_RUNTIME_PATHS = (SCRIPT_PATH, HARNESS_PATH, FAKE_PATH)

#: The constructs Windows PowerShell 5.1 does not understand.
INCOMPATIBLE = (
    (r"-AsHashtable", "ConvertFrom-Json -AsHashtable is PowerShell 6"),
    (r"\?\?", "the null-coalescing operator is PowerShell 7"),
    (r"&&", "the && pipeline chain is PowerShell 7"),
    (r"\|\|", "the || pipeline chain is PowerShell 7"),
    (r"-Parallel", "ForEach-Object -Parallel is PowerShell 7"),
    (r"\bJoin-String\b", "Join-String is PowerShell 6"),
    (r"\bTest-Json\b", "Test-Json is PowerShell 6"),
    (r"\bGet-Uptime\b", "Get-Uptime is PowerShell 6"),
    (r"\[System\.Text\.Json", "System.Text.Json is .NET Core only"),
    (r"\bFromHexString\b", "Convert.FromHexString is .NET Core only"),
    (r"\bToHexString(?:Lower)?\b", "Convert.ToHexString is .NET Core only"),
    (r"\[System\.HashCode\]", "System.HashCode is .NET Core only"),
    (r"\b(?:ReadOnly)?Span(?:`\d+)?\b", "Span is unavailable on the target framework"),
    (r"\[System\.(?:Index|Range)\]", "Index and Range are .NET Core only"),
    (
        r"\[System\.(?:Index|Range|HashCode)\]::new\(",
        "the constructor belongs to a .NET Core-only type",
    ),
    (r"\bConvertFrom-Json\b[^\n]*-AsHashtable", "the hashtable form of ConvertFrom-Json"),
)

#: The ternary of PowerShell 7: a variable, a question mark and a colon.
TERNARY = re.compile(r"\$[A-Za-z_][A-Za-z0-9_]*\s*\?")

#: A class of PowerShell 5.0: the helper must not define one.
CLASS_DECLARATION = re.compile(r"^\s*class\s+[A-Za-z_]", re.MULTILINE)

#: The cmdlets of the ScheduledTasks module, which do not work as the write
#: account (SPEC section 9).
SCHEDULED_TASKS = (
    "Register-ScheduledTask",
    "Unregister-ScheduledTask",
    "New-ScheduledTaskAction",
    "New-ScheduledTaskTrigger",
    "New-ScheduledTaskPrincipal",
    "New-ScheduledTaskSettingsSet",
    "Get-ScheduledTask",
    "Set-ScheduledTask",
    "Start-ScheduledTask",
    "Stop-ScheduledTask",
    "Get-ScheduledTaskInfo",
)


def _script() -> str:
    return SCRIPT_PATH.read_text(encoding="utf-8")


def _lines() -> list[str]:
    return _script().splitlines()


def test_the_helper_is_where_the_package_ships_it() -> None:
    """The helper is the file the setup installs."""
    assert SCRIPT_PATH.is_file()
    assert SCRIPT_PATH.name == "write.ps1"


def test_the_helper_reads_the_device_that_stands_for_the_domain() -> None:
    """The helper answers to the device that stands for the domain.

    Every DC of the domain answers to the name of the device that
    stands for it, and the file of the install holds that name: the
    comment of the reader says so.
    """
    text = _script()
    body = text[text.index("function Get-NewtonDeviceName") :]
    body = body[: body.index("\nfunction ")]
    comments = [
        line.strip() for line in body.splitlines() if line.strip().startswith("#")
    ]
    assert any("stands for the domain" in line for line in comments), comments


def test_the_helper_takes_only_the_undo_argument() -> None:
    """The helper takes no argument over SSH and one in the undo mode."""
    text = _script()
    assert re.search(r"^param\(\s*\[string\]\$Undo\s*\)", text, re.MULTILINE)
    assert "Set-StrictMode -Version 3" in text
    assert "$ErrorActionPreference = 'Stop'" in text


def test_the_main_body_runs_only_when_the_script_is_not_dot_sourced() -> None:
    """The tests dot-source the helper: only the functions are loaded."""
    text = _script()
    assert "if ($MyInvocation.InvocationName -ne '.')" in text
    assert text.index("if ($MyInvocation.InvocationName -ne '.')") > text.index(
        "function ConvertFrom-NewtonRequest"
    )


def test_no_construct_of_a_newer_powershell() -> None:
    """The helper is Windows PowerShell 5.1 code."""
    for path in POWERSHELL_RUNTIME_PATHS:
        text = path.read_text(encoding="utf-8")
        for pattern, why in INCOMPATIBLE:
            assert not re.search(pattern, text), f"{path.name}: {why}"
        assert not TERNARY.search(text), f"{path.name}: the ternary operator is PowerShell 7"
        assert not CLASS_DECLARATION.search(text), f"{path.name}: the helper defines no class"


def test_directory_protocols_is_loaded_before_the_first_type_use() -> None:
    """Windows PowerShell 5.1 needs the protocols assembly loaded explicitly."""
    text = _script()
    load = "Add-Type -AssemblyName System.DirectoryServices.Protocols"
    assert load in text
    assert text.index(load) < text.index("[System.DirectoryServices.Protocols.")


def test_the_helper_never_runs_anything_dynamic() -> None:
    """Nothing in the helper is built at run time."""
    text = _script()
    for pattern in (
        r"\binvoke-expression\b",
        r"\biex\b",
        r"\bstart-process\b",
        r"\badd-type\b[^\n]*-typedefinition",
        r"\bnew-object\b[^\n]*\bSystem\.CodeDom\b",
    ):
        assert not re.search(pattern, text, re.IGNORECASE), pattern


def test_the_helper_never_builds_a_password_in_plain_text() -> None:
    """The password of a user-create is never handed to a cmdlet."""
    text = _script()
    assert "-AsPlainText" not in text
    assert "ConvertTo-SecureString" not in text
    assert "AppendChar" in text
    assert "SecureStringToGlobalAllocUnicode" in text
    assert "ZeroFreeGlobalAllocUnicode" in text


def test_the_helper_never_uses_the_scheduled_tasks_cmdlets() -> None:
    """The undo task goes through the COM API (SPEC section 9)."""
    text = _script()
    for cmdlet in SCHEDULED_TASKS:
        assert cmdlet not in text, cmdlet
    assert "Schedule.Service" in text
    assert "RegisterTaskDefinition" in text
    assert "DeleteTask" in text


def test_the_helper_reads_one_request_of_at_most_64_kib() -> None:
    """The request comes on stdin and the limit is the one of the contract."""
    text = _script()
    assert "[Console]::In" in text
    assert "$script:MaxRequestBytes = 65536" in text
    assert "MAX_REQUEST_BYTES" not in text


def test_the_helper_has_its_own_json_scanner() -> None:
    """The scanner enforces the rules the JSON parser does not."""
    text = _script()
    assert "Test-NewtonJsonText" in text
    assert "Read-NewtonJsonString" in text
    assert "Read-NewtonJsonNumber" in text
    assert r"\A(0|[1-9][0-9]*)\z" in text
    assert "ToLowerInvariant()" in text
    assert "ConvertFrom-Json -InputObject" in text


def test_every_validation_pattern_uses_absolute_anchors() -> None:
    """A trailing newline never passes a schema validation pattern."""
    text = _script()
    for name in (
        "IntPattern",
        "DevicePattern",
        "TxidPattern",
        "TokenPattern",
        "RiskPattern",
        "GuidPattern",
        "SidPattern",
        "SamPattern",
        "ComputerSamPattern",
        "EpochPattern",
    ):
        match = re.search(rf"\$script:{name} = '([^']+)'", text)
        assert match is not None, name
        pattern = match.group(1)
        assert pattern.startswith(r"\A"), (name, pattern)
        assert pattern.endswith(r"\z"), (name, pattern)


def test_the_helper_sorts_the_canonical_keys_ordinally() -> None:
    """The keys of the canonical bytes are sorted by byte value."""
    text = _script()
    assert "[string]::CompareOrdinal" in text
    assert "Sort-Object" not in text


def test_the_helper_builds_the_digest_and_the_token() -> None:
    """The digest and the token are the ones of the contract."""
    text = _script()
    assert "newton-ad-request-v1" in text
    assert "newton-approval-v2" in text
    assert "SHA256" in text
    assert "HMACSHA256" in text
    assert "Test-NewtonConstantTime" in text


def test_the_helper_uses_one_ldap_adapter() -> None:
    """Every LDAP call goes through the adapter of the contract."""
    text = _script()
    for name in ("Search", "Modify", "ModifyDN", "Add", "Delete"):
        assert re.search(r"-Name " + name + " -Value", text), name
    assert "LdapConnection" in text
    assert "SessionOptions.Signing = $true" in text
    assert "SessionOptions.Sealing = $true" in text
    assert "GetHostEntry('')" in text
    assert re.search(r"\$connection\.Bind\(\)", text)
    assert "GetValues([string])" in text
    assert "GetValues([byte[]])" in text
    assert "GetValues([byte])" not in text
    assert re.search(
        r"SearchRequest\]::new\([^)]*\[string\[\]\]\$attrs", text, re.DOTALL
    )
    assert "return ,$attributes[$key]" in text
    assert "return ,$attribute" in text
    assert "PSObject.Properties['Response']" in text
    assert "PSObject.Properties['ResultCode']" in text


def test_the_helper_maps_the_measured_ldap_errors() -> None:
    """16 is a conflict, 50 is denied, 32 is not found."""
    text = _script()
    assert "if ($code -eq 16) { return 'conflict' }" in text
    assert "if ($code -eq 50) { return 'denied' }" in text
    assert "if ($code -eq 32) { return 'not_found' }" in text


def test_the_helper_builds_a_measured_directory_modification() -> None:
    """The DC exposes only the parameterless modification constructor."""
    text = _script()
    body = text[text.index("function New-NewtonDirectoryModification") :]
    body = body[: body.index("function Get-NewtonLdapAdapter")]
    assert "New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification" in body
    assert ".Name = $Name" in body
    assert ".Operation = $operationValue" in body
    assert ".Add($value)" in body
    assert "Activator" not in body


def test_the_pdc_check_compares_the_two_ntds_settings_dns() -> None:
    """RootDSE dsServiceName equals domain-head fSMORoleOwner on the PDC."""
    text = _script()
    body = text[text.index("function Test-NewtonIsPdc") :]
    body = body[: body.index("function Test-NewtonPrivilegedSid")]
    assert "return ($serviceName -ieq $owner)" in body
    assert "dNSHostName" not in body


def test_the_helper_walks_the_memberof_chain_with_a_cap() -> None:
    """The privileged walk is breadth first, with a visited set and a cap."""
    text = _script()
    assert "$script:PrivilegeDepthCap = 32" in text
    assert "Test-NewtonPrivilegedEntry" in text
    assert "Test-NewtonPrivilegedSid" in text
    assert "primaryGroupID" in text
    assert "objectSid" in text
    assert "SecurityIdentifier" in text


def test_the_helper_keeps_the_transaction_store() -> None:
    """The records live in their own directory and are created exclusively."""
    text = _script()
    assert "C:\\ProgramData\\Newton\\ad" in text
    assert "Open-NewtonFile -Path $Path -Mode 'CreateNew' -Access 'Write' -Share 'None'" in text
    assert "FileShare]::None" in text
    assert "Invoke-NewtonSweep" in text


def test_the_lock_opens_existing_files_with_read_only_access() -> None:
    """The measured write-account ACL can reopen only for read."""
    text = _script()
    body = text[text.index("function Enter-NewtonLock") :]
    body = body[: body.index("function Get-NewtonRecords")]
    assert "[System.IO.FileMode]::OpenOrCreate" in body
    assert "[System.IO.FileAccess]::Read" in body
    assert "[System.IO.FileAccess]::ReadWrite" not in body
    assert "[System.UnauthorizedAccessException]" in body
    assert "[Console]::Error.WriteLine" in body


def test_the_helper_arms_the_undo_with_the_com_api() -> None:
    """The undo task is a one-shot task of the root folder."""
    text = _script()
    assert "RegisterTaskDefinition($Name, $definition, 6, $null, $null, 2)" in text
    assert "GetFolder('\\').DeleteTask($Name, 0)" in text
    assert "LogonType = 2" in text
    assert "newton-undo-" in text
    assert "-Undo" in text


def test_the_helper_refuses_the_undo_over_ssh() -> None:
    """The undo never runs over an SSH session."""
    text = _script()
    assert "$env:SSH_CONNECTION" in text
    assert "$env:SSH_CLIENT" in text
    assert "$script:TxidPattern" in text


def test_the_helper_checks_the_acl_of_its_files() -> None:
    """Nobody but SYSTEM and Administrators may write the install."""
    text = _script()
    assert "Get-Acl" in text
    assert "FileSystemRights" in text
    assert "S-1-5-18" in text
    assert "S-1-5-32-544" in text
    body = text[text.index("function Test-NewtonRightsWritable") :]
    body = body[: body.index("function Test-NewtonSafeAcl")]
    for right in (
        "WriteData",
        "AppendData",
        "WriteExtendedAttributes",
        "WriteAttributes",
        "Delete",
        "DeleteSubdirectoriesAndFiles",
        "ChangePermissions",
        "TakeOwnership",
    ):
        assert f"FileSystemRights]::{right}" in body
    assert "FileSystemRights]::Write -bor" not in body
    assert "FileSystemRights]::Modify" not in body
    assert "FileSystemRights]::FullControl" not in body


def test_the_helper_never_writes_the_secret_down() -> None:
    """The secret is never in a record, an answer or a message."""
    text = _script()
    assert "if ($name -eq 'secret') { continue }" in text
    assert "Write-Verbose" not in text
    assert "Get-NewtonCanonicalValue $Request" in text


def test_the_harness_and_the_fake_are_shipped_with_the_tests() -> None:
    """The tests drive the helper through the harness."""
    assert HARNESS_PATH.is_file()
    assert FAKE_PATH.is_file()
    harness = HARNESS_PATH.read_text(encoding="utf-8")
    assert "newton_mcp/ad/collector/write.ps1" in harness
    assert "$script:LdapAdapter" in harness
    assert "$script:SchedulerAdapter" in harness


# ---------------------------------------------------------------------------
# the measured shapes of a real domain controller
# ---------------------------------------------------------------------------


def test_the_bit_maths_is_64_bit_and_never_a_big_number() -> None:
    """The bit maths of the contract is 64-bit."""
    text = _script()
    assert "BigInteger" not in text
    assert "$script:AccountDisable = [int64]2" in text
    assert "[int64]4194304" in text
    assert "ConvertTo-NewtonInt64" in text
    assert "-bnot $mask" in text
    assert "-bnot $script:AccountDisable" in text


def test_no_validation_pattern_uses_the_line_anchors() -> None:
    """A pattern of the helper is anchored with \\A and \\z."""
    text = _script()
    for match in re.finditer(r"\$script:\w+Pattern = '([^']+)'", text):
        pattern = match.group(1)
        # an escaped dollar is a literal dollar, not an anchor
        bare = pattern.replace(r"\$", "")
        assert "^" not in bare, pattern
        assert "$" not in bare, pattern
        assert pattern.startswith(r"\A"), pattern
        assert pattern.endswith(r"\z"), pattern
    assert "[regex]::IsMatch" not in text


def test_no_search_uses_an_empty_base_with_a_subtree_scope() -> None:
    """A search of a real DC never starts at the root."""
    text = _script()
    for match in re.finditer(r"Search-Newton \$Adapter '' '[^']*' '([^']*)'", text):
        assert match.group(1) == "base", match.group(0)
    assert "Search-Newton $Adapter ''" in text


def test_the_membership_of_a_group_is_never_read_whole() -> None:
    """The presence of a member is a base-scope search."""
    text = _script()
    body = text[text.index("function Test-NewtonMemberPresent") :]
    body = body[: body.index("function Find-NewtonObjectByGuid")]
    assert "'base'" in body
    assert "(member=" in body
    assert "ConvertTo-NewtonFilterText" in body
    assert "'member'" not in text[text.index("$script:ObjectReadAttributes") :][:400]


def test_every_record_write_is_a_new_append_only_file() -> None:
    """No transaction record is replaced, deleted or moved."""
    text = _script()
    assert "function Write-NewtonRecord" not in text
    assert "[System.IO.File]::Replace" not in text
    assert "[System.IO.File]::Delete" not in text
    assert "[System.IO.File]::Move" not in text
    assert "Open-NewtonFile -Path $Path -Mode 'CreateNew' -Access 'Write' -Share 'None'" in text
    assert "'<txid>.<n>.json'" in text


def test_spec_section_7_describes_the_measured_append_only_store() -> None:
    """The shared contract records the real DC constraints."""
    text = SPEC_PATH.read_text(encoding="utf-8")
    section = text[text.index("## 7. The transaction record and the undo") :]
    section = section[: section.index("## 8. Files the setup installs")]
    assert "<txid>.<n>.json" in section
    assert "highest" in section
    assert "append-only" in section
    assert "never deleted or rewritten" in section
    assert (
        "SYSTEM and Administrators Full, and newton-ops "
        "CreateFiles, Read, Synchronize with (OI)(CI) and NO Delete"
    ) in section
    assert "Samba helper may keep its own record scheme" in section
    assert "root-owned mode 0700" in section


def test_the_rules_of_the_verb_come_after_the_token() -> None:
    """The order of the checks: the token, the window, the replay, the rest."""
    text = _script()
    apply_body = text[text.index("function Invoke-NewtonApply") :]
    apply_body = apply_body[: apply_body.index("function Get-NewtonLiveAfter")]
    assert apply_body.index("Test-NewtonConstantTime") < apply_body.index(
        "Test-NewtonVerbRules"
    )
    assert apply_body.index("'expired'") < apply_body.index("Test-NewtonVerbRules")
    assert apply_body.index("'replay'") < apply_body.index("Test-NewtonVerbRules")
    mode_body = text[text.index("function Invoke-NewtonWriteMode") :]
    mode_body = mode_body[: mode_body.index("function Invoke-NewtonRequest")]
    assert "Test-NewtonVerbRules" not in mode_body


def test_only_a_record_that_exists_is_a_replay() -> None:
    """A broken store is an error, never a replay."""
    text = _script()
    body = text[text.index("function Invoke-NewtonApply") :]
    body = body[: body.index("function Get-NewtonLiveAfter")]
    assert body.index("Get-NewtonRecordInfo -Txid $txid") < body.index(
        "New-NewtonRecordExclusive"
    )
    assert "return (New-NewtonResponse 'replay')" in body
    assert "return (New-NewtonResponse 'error')" in body


def test_the_scanner_caps_the_nesting_of_a_request() -> None:
    """The scan of a request is linear."""
    text = _script()
    assert "$script:JsonDepthMax = 32" in text
    assert "if ($script:JsonDepth -ge $script:JsonDepthMax) { return $false }" in text


def test_the_privilege_walk_fails_closed() -> None:
    """The depth cap and a group that cannot be read are privileged."""
    text = _script()
    body = text[text.index("function Test-NewtonPrivilegedEntry") :]
    body = body[: body.index("function Test-NewtonNestedPrivileged")]
    assert "if ($Depth -ge $script:PrivilegeDepthCap) { return $true }" in body
    assert "if ($null -eq $group) { return $true }" in body


def test_the_move_of_an_object_is_a_rename() -> None:
    """A move is a ModifyDN, never a modify of distinguishedName."""
    text = _script()
    assert "ModifyDNRequest" in text
    body = text[text.index("function Invoke-NewtonWrite") :]
    body = body[: body.index("function Invoke-NewtonUndoWrite")]
    assert "$Adapter.ModifyDN(" in body
    assert "'OU=Domain Controllers,'" in text
    assert "'CN=Domain Controllers,'" not in text


def test_the_quota_of_the_domain_head_has_its_measured_name() -> None:
    """The quota attribute is ms-DS-MachineAccountQuota (MEASURED 2026-11-09)."""
    text = _script()
    assert "msDS-MachineAccountQuota" not in text
    assert "'ms-DS-MachineAccountQuota'" in text


def test_the_undo_of_a_user_create_reads_the_members_of_the_object() -> None:
    """The undo deletes a created user only when it has no member."""
    text = _script()
    body = text[text.index("function Find-NewtonCreatedObject") :]
    body = body[: body.index("function Get-NewtonRootDse")]
    assert "'member'" in body
    assert "'memberOf'" in body
    assert "uSNChanged" in body


def test_the_live_probe_for_a_real_dc_is_shipped() -> None:
    """The probe to run on a real DC is in the tests."""
    probe = Path(__file__).resolve().parent / "win_write_live_probe.ps1"
    assert probe.is_file()
    text = probe.read_text(encoding="utf-8")
    assert ". $HelperPath" in text or ". $helperPath" in text
    for check in (
        "bind",
        "rootdse",
        "pdc",
        "resolve",
        "tokengroups",
        "privileged",
        "dc_ou",
        "hex",
    ):
        assert check in text.lower(), check


# ---------------------------------------------------------------------------
# the names of the accounts are lowercased
# ---------------------------------------------------------------------------


def test_the_ids_of_an_answer_carry_the_names_in_lowercase() -> None:
    """Every sam of the ids is lowercased."""
    text = _script()
    assert "function ConvertTo-NewtonLowerSam" in text
    assert "return $Value.ToLowerInvariant()" in text
    body = text[text.index("function Get-NewtonTarget") :]
    body = body[: body.index("function Resolve-NewtonOne")]
    checked = 0
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped.startswith(("group_sam =", "member_sam =", "sam =")):
            continue
        assert "ConvertTo-NewtonLowerSam" in stripped, stripped
        checked += 1
    assert checked == 4


def test_the_name_of_a_request_meets_the_name_of_the_directory() -> None:
    """The two names are compared without their case."""
    text = _script()
    body = text[text.index("function Resolve-NewtonOne") :]
    body = body[: body.index("function Get-NewtonFacts")]
    assert "if ($live -ine $sam) { return $null }" in body
    assert "-ceq $sam" not in body


def test_the_live_probe_resolves_a_name_in_lowercase() -> None:
    """The live probe shows the lowercase name."""
    probe = Path(__file__).resolve().parent / "win_write_live_probe.ps1"
    text = probe.read_text(encoding="utf-8")
    assert "resolve_lower" in text
    assert "target = @{ sam = 'administrator' }" in text


# ---------------------------------------------------------------------------
# no collection index ever reaches the answer
# ---------------------------------------------------------------------------

#: The receivers of a collection method that the helper may keep, each named
#: with the reason why its value cannot reach the answer.
NAMED_RECEIVERS = {
    "$bytes": (
        "a System.Collections.Generic.List[byte]: its Add returns void, so it "
        "never carries an index"
    ),
    "$Adapter": (
        "the LDAP adapter of the helper: the runtime test of the real adapter "
        "proves that its Add puts nothing in the pipeline"
    ),
}

#: The receiver of a call of a collection: a variable and its properties.
RECEIVER = re.compile(
    r"(\$[A-Za-z_][A-Za-z0-9_]*(?::[A-Za-z_][A-Za-z0-9_]*)?"
    r"(?:\.[A-Za-z_][A-Za-z0-9_]*)*)\.(Add|Remove|Insert|AddRange|RemoveAt)\("
)


def _head_of_the_statement(text: str, position: int) -> str:
    """The text of the statement that holds the call, before the call."""
    start = text.rfind("\n", 0, position) + 1
    head = text[start:position]
    for separator in (";", "{", "}"):
        index = head.rfind(separator)
        if index >= 0:
            head = head[index + 1 :]
    return head.strip()


def _tail_of_the_line(text: str, position: int) -> str:
    """The text of the line of the call, after the call."""
    end = text.find("\n", position)
    if end < 0:
        end = len(text)
    return text[position:end]


def test_every_collection_call_of_the_helper_discards_its_value() -> None:
    """No collection index ever reaches the answer of a mode."""
    text = _script()
    checked = 0
    for match in RECEIVER.finditer(text):
        checked += 1
        head = _head_of_the_statement(text, match.start())
        tail = _tail_of_the_line(text, match.end())
        if head in ("[void]", "$null ="):
            continue
        if "| Out-Null" in tail:
            continue
        receiver = match.group(1)
        assert receiver in NAMED_RECEIVERS, (
            f"line {text.count(chr(10), 0, match.start()) + 1} keeps the value "
            f"of .{match.group(2)}: {match.group(0)}"
        )
    assert checked > 0


def test_the_ldap_collections_of_the_adapter_are_voided() -> None:
    """The four collection calls of the real adapter are voided."""
    text = _script()
    body = text[text.index("function New-NewtonLdapAdapter") :]
    body = body[: body.index("function New-NewtonDirectoryModification")]
    assert (
        "[void]$request.Modifications.Add((New-NewtonDirectoryModification 1 "
        "$Attribute @([string]$value)))" in body
    )
    assert (
        "[void]$request.Modifications.Add((New-NewtonDirectoryModification 0 "
        "$Attribute @([string]$value)))" in body
    )
    assert (
        "[void]$request.Attributes.Add([System.DirectoryServices.Protocols"
        ".DirectoryAttribute]::new([string]$name, $values))" in body
    )
    assert (
        "[void]$request.Attributes.Add([System.DirectoryServices.Protocols"
        ".DirectoryAttribute]::new([string]$name, [string[]]$texts))" in body
    )


def test_the_answer_of_a_mode_is_always_one_object() -> None:
    """The entry point answers error when a value leaks."""
    text = _script()
    assert "function ConvertTo-NewtonAnswer" in text
    start = text.index("function ConvertTo-NewtonAnswer")
    end = text.index("\nfunction ", start + 1)
    body = text[start:end]
    assert "[System.Collections.IDictionary]" in body
    assert "[Console]::Error.WriteLine" in body
    assert "New-NewtonResponse 'error'" in body
    # the guard is at the entry points: the request, the undo and the body
    assert text.count("ConvertTo-NewtonAnswer") >= 4
