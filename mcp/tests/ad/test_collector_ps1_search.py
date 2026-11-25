"""The error mapping of the search of the Windows AD collector, in PowerShell.

The collector runs on a Windows domain controller, where pytest never reaches
it.  The probe parses the collector, defines only its functions and its
script-scope settings, and runs one query against a fake searcher: the fake
raises the COM error the test names, either where the search starts (the bind
of the search root) or where a row that came back is read.

ADSI answers 0x8007200A ("the specified directory service attribute or value
does not exist") when it cannot read the search root itself.  Both the
``CN=Password Settings Container`` and the ``CN=MicrosoftDNS`` bases are
readable by the administrators and by the domain controllers only, so the
collector answers ``denied``/``access_denied`` there: it is an access problem
and not a missing object.  A row that came back is readable, so the same
error raised while a row is read stays what it was.

The last tests are the end of the road: the status the collector reports for
the search root is the status the audit reads, and an access problem has to
be an ``ACCESS_DENIED`` and never an ``ERROR``.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

import measured
from newton_mcp.ad import catalogue, model, runner
from pwsh_path import PWSH

AD_DIR = Path(__file__).resolve().parent
PROBE = AD_DIR / "collector_search_probe.ps1"
COLLECTOR = AD_DIR.parents[1] / "newton_mcp" / "ad" / "collector" / "collector.ps1"

# The error ADSI raises when it cannot read the search root itself.
UNREADABLE_ROOT = "0x8007200A"
# The error ADSI raises when the base does not exist.
MISSING_OBJECT = "0x80072030"


def _require_pwsh() -> None:
    if not PWSH.is_file():
        pytest.skip(f"PowerShell 7.4 is not installed at {PWSH}")


def _search(where: str, hresult: str) -> dict[str, Any]:
    """The result of one query of the collector, over a fake searcher."""
    _require_pwsh()
    finished = subprocess.run(
        [
            str(PWSH),
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(PROBE),
            str(COLLECTOR),
            where,
            hresult,
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert finished.returncode == 0, finished.stderr
    return json.loads(finished.stdout)


def _check_of(check_id: str) -> catalogue.Check:
    check = next(c for c in catalogue.CHECKS if c.id == check_id)
    return check


def _run(check_id: str, document: dict[str, Any]) -> model.CheckResult:
    """The result of one check over a document, through the runner."""
    report = runner.run(
        measured.parse(document), "ad-windows", checks=[_check_of(check_id)]
    )
    return report.results[0]


def test_a_search_root_the_account_cannot_read_is_denied() -> None:
    """The root of the search is what the account may not read: it is an
    access problem, and the collector says so."""
    result = _search("search", UNREADABLE_ROOT)

    assert result["status"] == "denied"
    assert result["error_code"] == "access_denied"
    assert result["rows"] == 0


def test_a_base_that_does_not_exist_is_still_no_such_object() -> None:
    """The mapping of the other root error does not move."""
    result = _search("search", MISSING_OBJECT)

    assert result["status"] == "unavailable"
    assert result["error_code"] == "no_such_object"


def test_an_attribute_of_a_row_that_cannot_be_read_is_still_an_error() -> None:
    """A row that came back is readable: the error of a row is not the
    error of the root, and it stays what it was."""
    result = _search("row", UNREADABLE_ROOT)

    assert result["status"] == "error"
    assert result["error_code"] == "other"


def test_a_search_that_works_still_reads_its_row() -> None:
    """The search and the rows are two steps now, and a search that works
    still reads its row."""
    result = _search("ok", UNREADABLE_ROOT)

    assert result["status"] == "ok"
    assert result["error_code"] == ""
    assert result["rows"] == 1


def test_the_password_settings_the_account_cannot_read_are_access_denied() -> None:
    """The end of the road: the status the collector reports for the
    search root is the status the audit reads."""
    status = _search("search", UNREADABLE_ROOT)
    document = measured.audit_json()
    measured.set_query_status(
        document, "psos", status["status"], status["error_code"]
    )

    result = _run("AD-A-35", document)

    assert result.status == model.Status.UNKNOWN
    assert result.reason == model.UnknownReason.ACCESS_DENIED


def test_the_dns_zones_the_account_cannot_read_are_access_denied() -> None:
    """The DNS partition is read the same way, and the checks of the
    zones say the same thing."""
    status = _search("search", UNREADABLE_ROOT)
    document = measured.audit_json()
    for query_id in ("dns_zones", "dns_ldap_srv"):
        measured.set_query_status(
            document, query_id, status["status"], status["error_code"]
        )

    for check_id in ("AD-A-68a", "AD-A-68b", "AD-A-69a", "AD-A-69b"):
        result = _run(check_id, document)
        assert result.status == model.Status.UNKNOWN, check_id
        assert result.reason == model.UnknownReason.ACCESS_DENIED, check_id
