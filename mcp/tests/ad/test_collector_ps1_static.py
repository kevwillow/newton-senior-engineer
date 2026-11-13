"""Static checks on the Windows AD collector script.

The collector runs on a Windows domain controller where pytest never reaches
it, so these checks pin the properties the collector contract depends on: it
takes no input, it runs nothing dynamic, a cpassword value can never reach the
document, the security descriptor asks for owner and DACL only, XML parsing
refuses DTDs, and the JSON depth is enough for the document shape.

The script itself is exercised by the maintainer in the lab; see
``mcp/newton_mcp/ad/collector/README-windows.md``.

``queries.json`` and ``forbidden.json`` are not kept beside the collector any
more: the canonical query set and the generated forbidden list are installed
next to the script by the core package.  The checks that need them run only
when the canonical copy is in the tree (``mcp/newton_mcp/ad/queries.json``).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

COLLECTOR_DIR = (
    Path(__file__).resolve().parents[2] / "newton_mcp" / "ad" / "collector"
)
SCRIPT_PATH = COLLECTOR_DIR / "collector.ps1"
QUERIES_PATH = COLLECTOR_DIR.parent / "queries.json"
FORBIDDEN_PATH = COLLECTOR_DIR.parent / "forbidden.json"

QUERY_IDS = [
    "domain_head",
    "users",
    "computers",
    "groups",
    "fsps",
    "gmsa",
    "kds_root_keys",
    "psos",
    "dir_service",
    "optional_features",
    "partitions",
    "schema_head",
    "schema_laps",
    "trusts",
    "adminsdholder",
    "protected_sds",
    "dc_ou",
    "gpos",
    "ous",
    "dpapi_backup",
    "pw_attr_presence",
    "keycred_presence",
]

FORBIDDEN_NAMES = {
    "unicodepwd",
    "dbcspwd",
    "ntpwdhistory",
    "lmpwdhistory",
    "pwdhistory",
    "supplementalcredentials",
    "userpassword",
    "unixuserpassword",
    "mssfu30password",
    "ms-mcs-admpwd",
    "mslaps-password",
    "mslaps-encryptedpassword",
    "mslaps-encryptedpasswordhistory",
    "mslaps-encrypteddsrmpassword",
    "mslaps-encrypteddsrmpasswordhistory",
    "msfve-recoverypassword",
    "msfve-keypackage",
    "msfve-recoveryguid",
    "msfve-volumeguid",
    "msds-managedpassword",
    "msds-managedpasswordid",
    "msds-managedpasswordpreviousid",
    "mskds-rootkeydata",
    "currentvalue",
    "priorvalue",
    "trustauthincoming",
    "trustauthoutgoing",
    "initialauthincoming",
    "initialauthoutgoing",
    "mspki-dpapimasterkeys",
    "mspki-credentialroamingtokens",
    "mspkiaccountcredentials",
    "mspkiroamingtimestamp",
    "msds-keycredentiallink",
}


def _script() -> str:
    return SCRIPT_PATH.read_text(encoding="utf-8")


def _lines() -> list[str]:
    return _script().splitlines()


def test_collector_script_is_present() -> None:
    assert SCRIPT_PATH.is_file()


def test_never_reads_stdin() -> None:
    text = _script().lower()
    assert "$input" not in text
    assert "[console]::in" not in text
    assert "read-host" not in text


def test_never_executes_anything_dynamic() -> None:
    text = _script()
    for pattern in (
        r"\binvoke-expression\b",
        r"\biex\b",
        r"\bstart-process\b",
        r"\badd-type\b",
    ):
        assert not re.search(pattern, text, re.IGNORECASE), pattern


def test_takes_no_arguments_and_no_input() -> None:
    text = _script()
    assert re.search(r"\$args\.Count", text)
    assert "Set-StrictMode -Version 3" in text
    assert "$ErrorActionPreference = 'Stop'" in text


def test_cpassword_value_is_never_read_into_a_variable() -> None:
    """The attribute value is tested for emptiness in place; it is never
    bound to a variable, so it cannot reach an output function."""
    for number, line in enumerate(_lines(), 1):
        if re.search(r"GetAttribute\(\s*['\"]cpassword['\"]\s*\)", line, re.IGNORECASE):
            assert "IsNullOrEmpty" in line, f"line {number}: cpassword read without a non-empty test"
        if re.search(r"\$\w*cpassword\w*\s*=", line, re.IGNORECASE):
            assert "GetAttribute" not in line, f"line {number}: a cpassword value is stored"


def test_cpassword_only_ever_appears_as_a_kind_label_or_a_count() -> None:
    for number, line in enumerate(_lines(), 1):
        if "cpassword" not in line.lower():
            continue
        lowered = line.lower()
        assert (
            "kind" in lowered
            or "getattribute" in lowered
            or "count" in lowered
            or "cpasswordvalue" in lowered
        ), f"line {number}: unexpected cpassword use"


def test_output_writers_do_not_mention_cpassword() -> None:
    for number, line in enumerate(_lines(), 1):
        if "ConvertTo-Json" in line or "[Console]::Out.Write" in line:
            assert "cpassword" not in line.lower(), f"line {number}"


def test_security_descriptor_asks_for_owner_and_dacl_only() -> None:
    text = _script()
    assert "SecurityMasks" in text
    assert re.search(
        r"SecurityMasks\s*=\s*\[System\.DirectoryServices\.SecurityMasks\]'Owner,Dacl'",
        text,
    )
    assert "Sacl" not in text


def test_xml_parsing_refuses_dtds() -> None:
    text = _script()
    assert re.search(
        r"DtdProcessing\s*=\s*\[System\.Xml\.DtdProcessing\]::Prohibit", text
    )
    assert re.search(r"XmlResolver\s*=\s*\$null", text)
    assert "<!DOCTYPE" in text
    assert "<!ENTITY" in text


def test_json_depth_is_at_least_ten() -> None:
    depths = [int(value) for value in re.findall(r"-Depth\s+(\d+)", _script())]
    assert depths
    assert max(depths) >= 10


def test_collector_refuses_unsafe_input_and_install() -> None:
    text = _script()
    assert "Get-Acl" in text
    assert "S-1-5-32-544" in text
    assert "S-1-5-18" in text
    assert "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464" in text
    assert "ReadAllBytes" in text
    assert "SHA256" in text


def _canonical_queries() -> dict:
    if not QUERIES_PATH.is_file():
        pytest.skip(f"the canonical query set is not in this tree ({QUERIES_PATH})")
    return json.loads(QUERIES_PATH.read_text(encoding="utf-8"))


def _canonical_forbidden() -> list:
    if not FORBIDDEN_PATH.is_file():
        pytest.skip(f"the generated forbidden list is not in this tree ({FORBIDDEN_PATH})")
    return json.loads(FORBIDDEN_PATH.read_text(encoding="utf-8"))


def test_query_set_matches_the_spec_table() -> None:
    data = _canonical_queries()
    assert data["v"] == 1
    ids = [query["id"] for query in data["queries"]]
    assert ids == QUERY_IDS
    for query in data["queries"]:
        assert query["scope"] in {"base", "sub"}
        assert query["limit"] <= 50000
        assert "distinguishedName" in query["attrs"]
        assert query["filter"].count("(") == query["filter"].count(")")
        assert ":=" not in query["filter"]


def test_forbidden_list_is_the_spec_list() -> None:
    names = _canonical_forbidden()
    assert isinstance(names, list)
    assert {name.lower() for name in names} == FORBIDDEN_NAMES
    assert all(name == name.lower() for name in names)


def test_no_query_asks_for_a_forbidden_attribute() -> None:
    queries = _canonical_queries()["queries"]
    for query in queries:
        for attribute in query["attrs"]:
            assert attribute.lower() not in FORBIDDEN_NAMES
        for attribute in query.get("binary", []):
            assert attribute.lower() not in FORBIDDEN_NAMES


def test_the_domain_sid_is_read_from_the_property_collection() -> None:
    """`[ADSI]$entry.objectSid` hands back a PropertyValueCollection, so the
    SID bytes are taken from the property collection, not from the property
    shortcut."""
    text = _script()
    assert "Properties['objectSid']" in text
    assert "$entry.objectSid" not in text


def test_a_run_without_a_domain_sid_fails() -> None:
    """An empty domain SID is never acceptable: the run ends with exit 1."""
    text = _script()
    fallback = "$domainSid = Get-SidFromQueryResult $queryResults 'domain_head'"
    refusal = "Write-Fail 1 'newton-ad collector: the domain sid is unknown'"
    assert fallback in text
    assert refusal in text
    assert text.index(fallback) < text.index(refusal)


def test_a_ranged_attribute_wins_over_the_exact_key() -> None:
    """A DC answers a 1600-member group with `member;range=0-1499` plus an
    empty `member`; the exact key must never be preferred over the range."""
    text = _script()
    assert not re.search(
        r"if\s*\(\$candidate\s*-eq\s*\$name\)\s*\{\s*\$exactKey\s*=\s*\$candidate;\s*break",
        text,
    )
    assert re.search(r"\$rangeKeys\.Count\s*-gt\s*0", text)


def test_an_unfinished_ranged_loop_marks_the_query_truncated() -> None:
    """A ranged list that cannot be finished is `truncated`/`size_limit`, never
    a partial list reported as `ok`."""
    text = _script()
    assert re.search(r"\['complete'\]", text)
    assert re.search(r"\$Truncated\.Value\s*=\s*\$true", text)
    assert re.search(r"\$rowTruncatedRef\.Value", text)
    assert re.search(r"\$errorCode\s*=\s*'size_limit'", text)


def test_the_collector_still_demands_the_query_set_at_install_time() -> None:
    """The copies are gone from the repository, but the installed collector
    still refuses to run without the query set and the forbidden list next to
    it."""
    text = _script()
    assert "queries.json" in text
    assert "forbidden.json" in text
    assert "the collector files are missing" in text


def test_an_empty_result_is_ok_with_no_rows() -> None:
    """An empty result is `ok` with zero rows: the core decides what an empty
    means. The collector no longer probes the base or the naming context."""
    text = _script()
    for removed in ("Resolve-EmptyQuery", "Test-QueryBase", "Test-NamingContextMatch"):
        assert removed not in text, removed
    assert "Get-NamingContextRoot" not in text
    assert "SkipDiagnosis" not in text


def test_every_searcher_is_given_a_search_root() -> None:
    """`New-Object DirectorySearcher($string)` uses the string as the FILTER,
    not as the search root, so every search ran against the default naming
    context. Every searcher is built empty and gets its root from a
    DirectoryEntry."""
    text = _script()
    assert "DirectorySearcher(" not in text
    created = re.findall(
        r"New-Object System\.DirectoryServices\.DirectorySearcher\b", text
    )
    rooted = re.findall(
        r"\$searcher\.SearchRoot\s*=\s*New-Object\s+"
        r"System\.DirectoryServices\.DirectoryEntry\(",
        text,
    )
    assert len(created) >= 2
    assert len(rooted) == len(created)


def test_the_security_identifier_is_built_with_an_offset() -> None:
    """`[SecurityIdentifier]::new($bytes)` throws; the byte-array form needs
    the offset argument."""
    text = _script()
    assert not re.search(r"SecurityIdentifier\]::new\(\s*\$bytes\s*\)", text)
    assert len(re.findall(r"SecurityIdentifier\]::new\(\$bytes,\s*0\)", text)) == 2


def test_the_security_descriptor_is_mapped_under_its_canonical_name() -> None:
    """The descriptor is loaded, but the row builder maps only the query's
    attrs, so it was dropped. When the query asks for it, it is mapped under
    `nTSecurityDescriptor`, base64."""
    text = _script()
    assert re.search(r"\[bool\]\$WithDescriptor", text)
    assert re.search(r"-ieq\s+'ntsecuritydescriptor'", text)
    assert "$map['nTSecurityDescriptor']" in text
    assert re.search(
        r"New-ResultRow \$result \$attributes \$rowTruncatedRef \$needDescriptor", text
    )


def test_a_follow_up_without_a_range_key_is_incomplete() -> None:
    """A follow-up result with no `<attr>;range=` key means the row is
    truncated, never that the list is complete."""
    text = _script()
    assert re.search(r"if\s*\(-not\s+\$sawRange\)\s*\{\s*break\s*\}", text)
    assert not re.search(r"\$last\s+-or\s+\(-not\s+\$sawRange\)", text)


def test_is_dc_comes_from_the_root_dse_host_name() -> None:
    """The CIM DomainRole read needs admin, so the audit account always read
    `is_dc: false`. The first label of the RootDSE `dnsHostName` is the
    local computer name on a DC."""
    text = _script()
    assert "Get-CimInstance" not in text
    assert "Get-WmiObject" not in text
    assert "DomainRole" not in text
    assert re.search(r"\$dnsHostName\s+-split", text)
    assert "$env:COMPUTERNAME" in text
    assert re.search(r"\$hostLabels\[0\]\s*-ieq\s+\$localName", text)


def test_an_unsubstituted_base_or_an_unknown_scope_is_an_error() -> None:
    text = _script()
    assert re.search(r"\$base\.Contains\('\{'\)", text)
    assert re.search(r"\$scopeName\s+-ne\s+'sub'", text)
