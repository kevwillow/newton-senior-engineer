"""The carry-over tests for four review findings.

Four defects came out of an earlier review and waited for the change that
wires ``checks_for`` into the plan and the apply:

1. the read-back was built from the facts of a batch, and a later
   section-level line drops the facts of the options it staged before
   it, so a staged option had no read-back at all;
2. an option that only loses a value has no fact either, so it had no
   read-back at all;
3. the ``uci-list`` probe kept its own small grammar and did not keep
   the limits the installed path's own checker keeps: a field is
   short, a line is short, every character is printable ASCII without
   a backslash, and a value cannot be in the list and out of it at the
   same time.

Every item has a test that says what must hold.  Nothing here contacts
a router.
"""

from __future__ import annotations

import pytest

from newton_mcp import noinstall_checks as checks
from newton_mcp import probes
from noinstall_fakes import FakeSession


# ---- the read-back of every staged option ----------------------------------


def read_back_of(batch: str, types=None) -> list[checks.Check]:
    """The read-back checks of the first class of a batch."""
    results = checks.checks_for(batch, types)
    assert results, batch
    return [check for check in results[0].mandatory if check.kind == "read-back"]


def test_an_added_option_before_a_section_line_still_has_a_read_back() -> None:
    """The read-back comes from the options the batch stages.

    A section-level line drops the fact of every option of its section
    that was staged before it, so a read-back built from the facts
    would be empty: the option the batch stages is read back from the
    batch itself.
    """
    batch = (
        "add_list dhcp.@dnsmasq[0].server='1.1.1.1'\n"
        "set dhcp.@dnsmasq[0]='dnsmasq'\n"
    )
    read_back = read_back_of(batch)
    assert len(read_back) == 1, read_back
    assert read_back[0].probe == "uci-list"
    assert read_back[0].args == ("dhcp.@dnsmasq[0].server", "+1.1.1.1")


def test_an_added_option_of_a_named_section_still_has_a_read_back() -> None:
    """The router's own read says what type the section is."""
    batch = (
        "add_list dhcp.dnsmasq.server='1.1.1.1'\n"
        "set dhcp.dnsmasq='dnsmasq'\n"
    )
    read_back = read_back_of(batch, types={("dhcp", "dnsmasq"): "dnsmasq"})
    assert len(read_back) == 1, read_back
    assert read_back[0].probe == "uci-list"
    assert read_back[0].args == ("dhcp.dnsmasq.server", "+1.1.1.1")


def test_an_option_that_only_loses_a_value_still_has_a_read_back() -> None:
    """A value the batch takes away has no fact, and no read-back either.

    The check says the value must NOT be in the list: the list the
    router holds is not known, so the check says what must not be in
    it.
    """
    batch = "del_list dhcp.@dnsmasq[0].server='1.1.1.1'\n"
    read_back = read_back_of(batch)
    assert len(read_back) == 1, read_back
    assert read_back[0].probe == "uci-list"
    assert read_back[0].args == ("dhcp.@dnsmasq[0].server", "-1.1.1.1")


def test_the_sugar_that_loses_a_value_still_has_a_read_back() -> None:
    """``set cfg.opt-='v'`` is uci sugar for ``del_list``."""
    batch = "set dhcp.@dnsmasq[0].server-='1.1.1.1'\n"
    read_back = read_back_of(batch)
    assert len(read_back) == 1, read_back
    assert read_back[0].probe == "uci-list"
    assert read_back[0].args == ("dhcp.@dnsmasq[0].server", "-1.1.1.1")


# ---- the limits of the uci-list check --------------------------------------


@pytest.mark.parametrize(
    "args",
    (
        # a field longer than 128 bytes
        ("dhcp.@dnsmasq[0].server", "+" + "x" * 200),
        # a line longer than 512 bytes
        ("dhcp.@dnsmasq[0].server", *("+" + "x" * 120 for _ in range(5))),
        # a character that is not printable ASCII
        ("dhcp.@dnsmasq[0].server", "+\x01bad"),
        # a backslash
        ("dhcp.@dnsmasq[0].server", "+bad\\value"),
        # the same value in the list and out of it
        ("dhcp.@dnsmasq[0].server", "+1.1.1.1", "-1.1.1.1"),
    ),
)
def test_an_argument_the_installed_limits_refuse_never_reaches_the_router(
    args: tuple[str, ...],
) -> None:
    """The probe that exists only here keeps the same limits.

    The installed path's own checker refuses a probe whose fields are
    too long, whose line is too long, whose characters are not
    printable ASCII, and a value that has to be in the list and out of
    it at the same time.  The no-install probe keeps the same limits.
    """
    session = FakeSession({("*", "*"): {}})
    result = checks.run_probe(session, "uci-list", list(args))
    assert result.passed is None, (args, result)
    assert session.calls == [], (args, session.calls)


def test_the_uci_list_check_keeps_the_limits_of_the_installed_path() -> None:
    """The limits are the ones the installed path's own checker keeps."""
    assert probes.MAX_PROBE_FIELD_BYTES == 128
    assert probes.MAX_PROBE_LINE_BYTES == 512


def test_a_list_check_that_fits_still_runs() -> None:
    """The limits do not refuse a check the batch really stages."""
    session = FakeSession({("uci", "get"): {"value": ["1.1.1.1"]}})
    result = checks.run_probe(
        session, "uci-list", ["dhcp.@dnsmasq[0].server", "+1.1.1.1"]
    )
    assert result.passed is True, result
    assert session.calls, session.calls
