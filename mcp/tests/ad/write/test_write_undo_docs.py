"""The docs say what the AD undo does.

The undo is armed on the DC until Newton confirms; the apply confirms or
aborts before it returns, so an abort works only on a change still
armed (an apply cut off before its confirm).  Once confirmed, Newton
does not undo a change: the owner plans the reverse change.  An unlock
has no undo and is written at once, so no doc may list it among the
changes with an undo.
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path
from typing import Any

import pytest

import newton_mcp.server as server


REPO_ROOT = Path(__file__).resolve().parents[4]


def _flat(text: str) -> str:
    return " ".join(text.split())


# The release docs, in a tree that has them under docs/release/.  Where
# such a file is absent, the doc on the right is the release doc.
_RENAMED = {
    "docs/release/README-1.0.md": "README.md",
    "docs/release/ROADMAP-public.md": "docs/ROADMAP.md",
}


def _path(relative: str) -> Path:
    """The path of a doc.  Where the docs/release/ file is absent, the doc
    on the right of ``_RENAMED`` is the release doc."""
    path = REPO_ROOT / relative
    if relative in _RENAMED and not path.exists():
        return REPO_ROOT / _RENAMED[relative]
    return path


def _read(relative: str) -> str:
    return _flat(_path(relative).read_text(encoding="utf-8"))


def _unreleased() -> str:
    text = _read("CHANGELOG.md")
    start = text.index("## [1.4.0]")
    end = text.index("## [", start + 3)
    return text[start:end]


def _skill_ad_changes() -> str:
    text = _read("SKILL.md")
    start = text.index("### Changes: plan, approve, apply")
    end = text.index("### What Newton does not change", start)
    return text[start:end]


def _roadmap_row(relative: str) -> str:
    for line in _path(relative).read_text(encoding="utf-8").splitlines():
        if line.startswith("| 1.4.0 |"):
            return _flat(line)
    raise AssertionError(f"{relative} has no 1.4.0 row")


def _readme_ad_line() -> str:
    text = _read("docs/release/README-1.0.md")
    start = text.index("**Released: 1.4.0.**")
    end = text.index("Planned, with no dates:", start)
    return text[start:end]


def _tools() -> dict[str, str]:
    from mcp.shared.memory import create_connected_server_and_client_session

    async def listed() -> Any:
        async with create_connected_server_and_client_session(
            server.mcp._mcp_server
        ) as session:
            await session.initialize()
            return await session.list_tools()

    return {
        tool.name: _flat(str(tool.description))
        for tool in asyncio.run(listed()).tools
    }


def _docs() -> dict[str, str]:
    tools = _tools()
    return {
        "SKILL.md": _skill_ad_changes(),
        "CHANGELOG.md": _unreleased(),
        "README-1.0.md": _readme_ad_line(),
        "ROADMAP.md": _roadmap_row("docs/ROADMAP.md"),
        "ROADMAP-public.md": _roadmap_row("docs/release/ROADMAP-public.md"),
        "abort tool": tools["newton_ad_abort_change"],
        "apply tool": tools["newton_ad_apply_change"],
    }


# A list of the changes with an undo that names unlock among them.
_UNLOCK_IN_UNDO_LIST = re.compile(r"clean undo \([^)]*\bunlock\b")


@pytest.mark.parametrize("name", list(_docs()))
def test_no_doc_says_the_abort_undoes_a_confirmed_change(name: str) -> None:
    text = _docs()[name]
    assert "runs the undo now" not in text, name
    assert "is confirmed once written, so its abort is refused" not in text, name
    assert "Newton writes changes that have a clean undo" not in text, name
    assert "changes that have a clean undo" not in text, name
    assert "changes with a clean undo" not in text, name
    assert not _UNLOCK_IN_UNDO_LIST.search(text), name


@pytest.mark.parametrize(
    "name",
    ["SKILL.md", "CHANGELOG.md", "README-1.0.md", "ROADMAP.md", "ROADMAP-public.md"],
)
def test_the_docs_say_the_undo_lasts_until_the_confirm(name: str) -> None:
    text = _docs()[name]
    assert "armed on the domain controller until Newton confirms" in text, name
    assert "once confirmed, Newton does not undo it" in text.replace("Once", "once"), name
    assert "unlock has no undo and is written at once" in text, name


@pytest.mark.parametrize("name", ["SKILL.md", "CHANGELOG.md", "abort tool"])
def test_the_abort_works_only_on_a_change_still_armed(name: str) -> None:
    text = _docs()[name]
    assert "only on a change still armed" in text, name
    assert "cut off before its confirm" in text, name


@pytest.mark.parametrize("name", ["SKILL.md", "CHANGELOG.md", "apply tool"])
def test_the_apply_confirms_or_aborts_before_it_returns(name: str) -> None:
    assert "confirms or aborts before it returns" in _docs()[name], name


def test_the_two_roadmap_rows_are_the_same() -> None:
    assert _roadmap_row("docs/ROADMAP.md") == _roadmap_row(
        "docs/release/ROADMAP-public.md"
    )


def _readme_ad_section() -> str:
    text = _read("docs/release/README-1.0.md")
    start = text.index("### Active Directory")
    end = text.index("## How a change works", start)
    return text[start:end]


def _failure_docs() -> dict[str, str]:
    tools = _tools()
    return {
        "SKILL.md": _skill_ad_changes(),
        "CHANGELOG.md": _unreleased(),
        "README AD section": _readme_ad_section(),
        "apply tool": tools["newton_ad_apply_change"],
        "abort tool": tools["newton_ad_abort_change"],
    }


@pytest.mark.parametrize("name", list(_failure_docs()))
def test_the_docs_say_what_a_failed_connection_mid_apply_does(name: str) -> None:
    """A session to the DC that fails mid-apply: the owner reads the status,
    and the DC itself undoes a change that is not confirmed at undo_at."""
    text = _failure_docs()[name]
    assert "connection to a domain controller fails" in text, name
    assert "newton_ad_change_status" in text, name
    assert "undo_at" in text, name


@pytest.mark.parametrize("name", ["SKILL.md", "CHANGELOG.md", "apply tool"])
def test_the_docs_name_the_states_of_a_lost_step(name: str) -> None:
    text = _failure_docs()[name]
    for state in ("apply_unknown", "confirm_unknown", "abort_failed"):
        assert state in text, (name, state)


#: What an unlock's record reads once the unlock is written: the record
#: write can fail, and either helper then keeps the record armed (write.ps1
#: when its confirmed generation cannot be written; the Samba helper when
#: the ok path's record write raises and the settle cannot write it either).
UNLOCK_RECORD_CLAUSE = (
    "normally records it `confirmed` then (a DC that cannot write that record keeps it armed)"
)
#: The narrower wording, which names only a Windows DC.
UNLOCK_WINDOWS_ONLY = "a Windows DC that cannot write that record keeps it armed"


@pytest.mark.parametrize("name", ["README AD section", "SKILL.md"])
def test_the_docs_say_an_unlock_record_reads_confirmed_only_when_it_was_written(name: str) -> None:
    """An unlock stays written once it is written on the PDC, and its record
    normally reads confirmed then; a Windows DC that cannot write that record
    keeps it armed, so no doc says it is confirmed as soon as it is written."""
    text = " ".join(_failure_docs()[name].split())
    assert "as soon as every domain controller shows it" not in text
    assert "confirmed as soon as it is written" not in text, name
    assert UNLOCK_RECORD_CLAUSE in text, name


@pytest.mark.parametrize("name", ["README AD section", "CHANGELOG.md"])
def test_the_live_ad_runs_say_their_log_is_not_kept(name: str) -> None:
    text = {"README AD section": _readme_ad_section(), "CHANGELOG.md": _unreleased()}[name]
    assert "the log of those runs is not kept in this repository" in text, name


def test_the_readme_scopes_the_third_value_to_an_error_the_server_did_not_answer() -> None:
    """A third value after an error the server did not answer itself is
    apply_unknown; after a code the server answered it is a conflict and
    nothing was written."""
    text = _flat(_readme_ad_section())
    assert (
        "a failed write whose re-read shows neither the before-image nor the after-image"
        " after an error the server did not answer itself (on Samba a lost connection or a"
        " busy or unavailable server; on Windows a reply with no result code, while a busy"
        " reply the server sent counts as answered) is `apply_unknown`"
    ) in text
    assert "after a code the server answered, the result is a `conflict` and nothing was written" in text


# ---- which write helper code ran live ----------------------------------------


def _provenance() -> str:
    text = _readme_ad_section()
    start = text.index("The live runs (2026-11-12)")
    end = text.index("- ✓ A read-only audit", start)
    return text[start:end]


def _setup_bullet() -> str:
    for line in _path("docs/release/README-1.0.md").read_text(encoding="utf-8").splitlines():
        if "The four write setups" in line:
            return _flat(line)
    raise AssertionError("the README has no write setup bullet")


def test_the_readme_says_both_write_helpers_changed_after_the_live_runs() -> None:
    """Both write helpers changed after the 2026-11-12 runs: the README
    never says the Samba helper that ships is the one that ran live, and
    names the changes of each helper that are covered by tests only."""
    text = _provenance()
    assert "The Samba write helper is the one that ran live" not in text
    assert "Both write helpers changed after those runs" in text
    assert "covered by tests only" in text
    for words in (
        "sweep timer",
        "an unlock whose write failed",
        "the confirm reads the record again",
        "a third value",
        "the before-image after a failure with no answer from the server stays armed",
    ):
        assert words in text, words


def test_the_readme_setup_bullet_scopes_the_sweep_timer_to_tests() -> None:
    text = _setup_bullet()
    assert "newton-ad-sweep.timer" in text
    assert "added after those runs and is covered by tests only" in text


# ---- the contract says what both helpers do after a failed write -------------


SPEC = "docs/proposals/ad/SPEC-1.4-REQUEST.md"


def _spec_between(start: str, end: str) -> str:
    text = _read(SPEC)
    first = text.index(start)
    return text[first:text.index(end, first)]


def test_the_spec_says_a_failed_write_is_settled_by_what_the_directory_shows() -> None:
    text = _spec_between("If step 6 fails", "### The other modes")
    for stale in (
        "The Samba helper disarms its timer and runs the undo",
        "its undo records `undo_failed` rather than delete",
        "An `unlock` arms no undo and is `refused`",
        "any other value is undone now",
    ):
        assert stale not in text, stale
    for words in (
        "with no answer from the server stays `armed`",
        "the after-image after an error the server did not answer",
        "the after-image after an error the server answered",
        "a third value after an error the server answered is `refused`",
        "a third value after an error the server did not answer is `undo_failed`",
        "an `unlock` showing the after-image is `confirmed`",
    ):
        assert words in text, words


def test_the_spec_says_an_armed_unlock_abort_is_refused() -> None:
    text = _spec_between("- **`abort`**", "- **`status`**")
    assert "The abort of an `unlock` is refused with `conflict`" in text


def test_the_spec_names_the_sweep_argv() -> None:
    text = _spec_between("## 1. Transport", "## 2. Request fields")
    assert "`--sweep`" in text
    assert "refused when `SUDO_USER` is set" in text
    assert "takes no other argument" in text


def test_the_spec_says_an_undo_failed_record_is_final() -> None:
    text = _spec_between("**The start-up sweep:**", "## 8.")
    assert "an undo that failed is retried" not in text
    assert "`undo_failed` record is final and is never retried" in text


# ---- the apply tool says when a refused confirm is not_confirmed ---------------


def test_the_apply_description_names_conflict_the_confirmed_record_and_no_unlock_dc_state() -> None:
    text = _tools()["newton_ad_apply_change"]
    assert "answers the confirm with an error or a conflict after every DC showed the change" in text
    assert "a record that reads confirmed makes the result confirmed" in text
    assert "dc_state is absent when the record cannot be read and for an unlock" in text


# ---- the after-image after an error the server answered ---------------------


def test_the_readme_says_an_after_image_after_an_answered_error_is_a_conflict() -> None:
    text = _readme_ad_section()
    assert (
        "after a code the server answered, the result is a `conflict` and nothing was written,"
        " even when the re-read shows the after-image"
    ) in text


@pytest.mark.parametrize(
    "relative",
    ["mcp/newton_mcp/ad/collector/README-samba-write.md",
     "mcp/newton_mcp/ad/collector/README-windows-write.md"],
)
def test_the_helper_readmes_undo_now_only_after_an_error_the_server_did_not_answer(
    relative: str,
) -> None:
    text = _read(relative)
    assert "the after-image runs the undo at once" not in text
    assert "the after-image is undone at once" not in text
    assert "the after-image after an error the server itself answered is somebody else's same change" in text


def test_the_changelog_confirms_a_failed_unlock_only_after_an_unanswered_error() -> None:
    text = _unreleased()
    assert "`confirmed` when the account shows the after-image," not in text
    assert "an after-image after the DC's own error code is somebody else's same change" in text


# ---- busy replies, not_sent, a second apply, no-GUID undo, answered marks ----


def test_the_spec_says_a_busy_reply_counts_as_answered_on_windows() -> None:
    text = _read("docs/proposals/ad/SPEC-1.4-REQUEST.md")
    assert "anything else (a client timeout, a dropped or busy connection)" not in text
    assert "a busy reply the server sent counts as answered" in text


def test_the_changelog_scopes_not_sent_to_the_ssh_runner() -> None:
    text = _unreleased()
    assert "An apply request Newton refuses before it leaves the Newton host is recorded" not in text
    assert "the transport's own size refusal" in text
    assert "keeps the code `schema`" in text


def test_the_apply_tool_scopes_not_sent_to_the_ssh_runner() -> None:
    text = _flat(_tools()["newton_ad_apply_change"])
    assert "An apply request Newton refuses before it is sent is refused with code not_sent" not in text
    assert "An apply request the SSH runner refuses before it is sent" in text


def test_the_docs_say_a_second_apply_of_a_plan_that_reached_the_dc_is_never_sent() -> None:
    for name, text in (("CHANGELOG", _unreleased()), ("SKILL.md", _skill_ad_changes()),
                       ("server", _tools()["newton_ad_apply_change"])):
        flat = _flat(text)
        assert "or may have" in flat, name
        assert "`not_sent`" in flat or "not_sent" in flat, name


def test_the_docs_say_a_new_user_with_no_guid_is_never_undone_by_name() -> None:
    changelog = _unreleased()
    assert "and a Windows DC names its DN as the conflict" not in changelog
    assert "never `undone` from a lookup by its name" in changelog
    for relative in ("mcp/newton_mcp/ad/collector/README-windows-write.md",
                     "mcp/newton_mcp/ad/collector/README-samba-write.md"):
        assert "never `undone` from a lookup by its name" in _read(relative), relative
    samba = _read("mcp/newton_mcp/ad/collector/README-samba-write.md")
    assert "(a new user that is not there any more counts as put back)" not in samba


def test_the_docs_say_an_answered_write_marks_its_record() -> None:
    for relative in ("mcp/newton_mcp/ad/collector/README-windows-write.md",
                     "mcp/newton_mcp/ad/collector/README-samba-write.md"):
        text = _read(relative)
        assert "marks the record" in text, relative
        assert "never `conflict`" in text, relative
    assert "marks the record" in _unreleased()


SPEC = "docs/proposals/ad/SPEC-1.4-REQUEST.md"
SAMBA_README = "mcp/newton_mcp/ad/collector/README-samba-write.md"
WINDOWS_README = "mcp/newton_mcp/ad/collector/README-windows-write.md"


def test_the_docs_scope_the_answer_to_a_refused_record_that_cannot_be_written() -> None:
    """The answer that is never conflict is the one given when the refused
    record cannot be written; with the record written, the after-image or a
    third value after an answered error is a conflict.  On Samba it is the
    write's own code (error for one that maps to conflict), on Windows
    error."""
    samba = _read(SAMBA_README)
    assert "and then answers the write's own code, never `conflict`" not in samba
    assert ("when that record cannot be written, the answer is the write's own code "
            "(`error` for one that maps to `conflict`), never `conflict`") in samba
    windows = _read(WINDOWS_README)
    assert "then answers the error code, never `conflict`" not in windows
    assert "when that record cannot be written, the answer is `error`, never `conflict`" in windows
    spec = _read(SPEC)
    assert "and the answer is then the error code (never `conflict`)" not in spec
    assert ("when that record cannot be written, the answer is the write's own code on Samba "
            "(`error` for one that maps to `conflict`) and `error` on Windows, never `conflict`") in spec


def test_the_docs_say_an_unreadable_target_after_an_answered_error_is_never_undone() -> None:
    """A target that cannot be read again stays armed, but after an error
    the server answered its mark makes the timer or task record it refused
    and write nothing: it is never undone."""
    spec = _read(SPEC)
    assert "- a target that cannot be read again: the record stays `armed`, and the timer or task undoes it at `undo_at`;" not in spec
    assert ("after an error the server answered, the mark makes the timer or task "
            "record it `refused` and write nothing") in spec
    windows = _read(WINDOWS_README)
    assert ("after an error the server answered, the mark makes the task record it "
            "`refused` and write nothing") in windows
    samba = _read(SAMBA_README)
    assert ("after an error the server itself answered, the mark makes the timer or the sweep "
            "record it `refused` and write nothing") in samba


def test_the_spec_scopes_an_object_that_cannot_be_looked_up_after_an_undo() -> None:
    """On Windows an object that cannot be looked up again leaves the record
    armed; on Samba it does so only after an undo whose answer was lost, and
    an undo the server answered with an error is undo_failed."""
    spec = _read(SPEC)
    assert "and an object that cannot be looked up leaves the record `armed`." not in spec
    assert ("an object that cannot be looked up leaves the record `armed` (on Samba only after "
            "an undo whose answer was lost: an undo the server answered with an error wrote "
            "nothing and is `undo_failed`).") in spec


# ---- a store that takes neither the mark nor the refused record -------------

#: The condition every copy of the "no later undo writes anything" claim
#: names: the claim holds only while the mark or the refused record is on
#: the DC's disk.
UNMARKED_CLAUSE = "takes neither the mark nor the refused record"


@pytest.mark.parametrize(
    "relative",
    ["CHANGELOG.md", SPEC, SAMBA_README, WINDOWS_README, "docs/release/README-1.0.md"],
)
def test_the_docs_scope_the_answered_mark_to_a_store_that_took_it(relative: str) -> None:
    """After an error the server answered, no later undo writes anything
    only while the mark (or the refused record) is on the disk.  A store
    that takes neither leaves an armed record with no mark, which the
    sweep cannot tell from a lost answer: every copy of the claim names
    that limit, the ``unmarked`` answer and apply_unknown."""
    text = _unreleased() if relative == "CHANGELOG.md" else _read(relative)
    assert UNMARKED_CLAUSE in text, relative
    assert "`unmarked`" in text, relative
    assert "may write the before-image over somebody else's" in text, relative


def test_the_changelog_no_longer_says_no_later_undo_writes_anything_unqualified() -> None:
    text = _unreleased()
    assert ("so no later undo of it (the timer or task, the sweep, an abort) writes anything;"
            " the undo is cancelled") not in text


# ---- the Samba sweep timer exists only on a DC set up with this release -----

SWEEP_QUALIFIER = "a Samba DC whose write setup was run with this release"


def test_the_docs_scope_the_samba_sweep_timer_to_a_dc_set_up_with_this_release() -> None:
    """Only a DC whose write setup was run (or run again) with this release
    has the sweep timer; an older one retries at the next Newton request."""
    from newton_mcp.ad.write import apply as ad_apply

    for name, text in (
        ("SKILL.md", _skill_ad_changes()),
        ("README AD section", _readme_ad_section()),
        ("apply docstring", _flat(ad_apply.__doc__ or "")),
    ):
        assert "a Samba DC's sweep timer retries" not in text, name
        assert "a Samba domain controller's sweep timer retries" not in text, name
        assert SWEEP_QUALIFIER in text or SWEEP_QUALIFIER.replace("DC", "domain controller") in text, name


# ---- an unlock's confirm --------------------------------------------------------


def test_the_changelog_never_says_what_an_unlock_record_reads_or_that_a_conflict_is_a_lockout() -> None:
    text = _unreleased()
    assert "an unlock is recorded `confirmed` when it is written, so for an unlock the result says so" not in text
    assert "a conflict says the PDC emulator read the account locked again" not in text
    assert "may have read the account locked again" in text
    assert "a DC that cannot write that record keeps it armed" in text
    assert UNLOCK_WINDOWS_ONLY not in text


# ---- the AD setup commands in their installed form ----------------------------


def test_the_readme_gives_the_ad_setup_commands_in_their_installed_form() -> None:
    """On an installed Newton the setup scripts are printed by
    /opt/newton/scripts/newton-ad-setup; /usr/local/bin/newton-ad-setup takes
    only approval-key."""
    text = _readme_ad_section()
    assert "/opt/newton/scripts/newton-ad-setup write windows|samba" in text
    assert "docs/INSTALL.md" in text


# ---- a write that was never sent never reads armed on Samba ------------------

NEVER_SENT_CLAUSE = "reads `armed` only once its undo timer is armed, right before the write"


@pytest.mark.parametrize("relative", ["CHANGELOG.md", SPEC, SAMBA_README])
def test_the_docs_say_a_samba_record_reads_armed_only_right_before_the_write(relative: str) -> None:
    """The Samba record is created refused and reads armed only once its
    timer is armed, so a store that refuses a later write never leaves armed
    a change that was never sent (which the sweep would undo over somebody
    else's change).  A Windows task that cannot be registered whose refused
    record cannot be written answers unmarked."""
    text = _unreleased() if relative == "CHANGELOG.md" else _read(relative)
    assert NEVER_SENT_CLAUSE in text, relative
    if relative != SAMBA_README:
        assert "a task that cannot be registered" in text, relative


def test_the_windows_readme_scopes_a_confirmed_unlock_to_a_record_that_was_written() -> None:
    """write.ps1 swallows a confirmed record of an unlock that cannot be
    written: the unlock then stays armed."""
    text = _read(WINDOWS_README)
    assert "(an unlock, which has no undo, is confirmed);" not in text
    assert "or stays armed when that record cannot be written" in text


# ---- a record write that fails is read back ---------------------------------

#: Both helpers read a record back after its write fails: the write can fail
#: after the record reached the disk (a flush that failed).
READ_BACK_CLAUSE = "a record write that fails is read back, and the helper acts on what the disk holds"
#: An armed record of a write that was never sent, which the store would not
#: let the helper write refused again.
NEVER_SENT_UNMARKED_CLAUSE = (
    "an armed record of a write that was never sent that cannot be written `refused` again answers with `unmarked`"
)


@pytest.mark.parametrize("relative", ["CHANGELOG.md", SPEC, SAMBA_README, WINDOWS_README])
def test_the_docs_say_a_failed_record_write_is_read_back(relative: str) -> None:
    """write_record (Samba) and the append of a generation (Windows) can
    raise after the record reached the disk.  The docs say the helper reads
    it back, and that a never-sent write whose armed record cannot be
    written refused again answers unmarked; no doc says such a record never
    reads armed."""
    text = _unreleased() if relative == "CHANGELOG.md" else _read(relative)
    text = " ".join(text.split())
    assert READ_BACK_CLAUSE in text, relative
    assert NEVER_SENT_UNMARKED_CLAUSE in text, relative
    assert "so no record of a write that was never sent reads `armed`" not in text, relative
    assert "never leaves armed a change that was never sent" not in text, relative


# ---- an unlock record either DC cannot write --------------------------------


@pytest.mark.parametrize("name", ["README AD section", "SKILL.md", "CHANGELOG.md"])
def test_no_doc_says_only_a_windows_dc_keeps_an_unlock_armed(name: str) -> None:
    """A Samba DC whose confirmed record of an unlock cannot be written keeps
    it armed too: the sentence names a DC, not a Windows DC."""
    text = " ".join(_failure_docs()[name].split())
    assert UNLOCK_WINDOWS_ONLY not in text, name


def test_the_changelog_says_a_dc_that_cannot_write_an_unlock_record_keeps_it_armed() -> None:
    text = " ".join(_unreleased().split())
    assert (
        "the DC normally records an unlock `confirmed` when it is written, and a DC that"
        " cannot write that record keeps it armed"
    ) in text


def test_the_samba_readme_says_an_unlock_record_it_cannot_write_stays_armed() -> None:
    text = " ".join(_read(SAMBA_README).split())
    assert (
        "An unlock that is written is recorded `confirmed`, or stays armed when that record"
        " cannot be written"
    ) in text


#: A read-back that itself fails says nothing about the disk: the helper
#: acts as if the armed record landed.
UNREADABLE_WORST_CASE_CLAUSE = (
    "a read-back that fails counts as the armed record having landed"
)


@pytest.mark.parametrize("relative", ["CHANGELOG.md", SPEC, SAMBA_README, WINDOWS_README])
def test_the_docs_say_an_unreadable_read_back_counts_as_landed(relative: str) -> None:
    text = _unreleased() if relative == "CHANGELOG.md" else _read(relative)
    text = " ".join(text.split())
    assert UNREADABLE_WORST_CASE_CLAUSE in text, relative


# ---- what an unlock's record reads, in the shipped strings ------------------

#: The qualifier the docs give "confirmed once written": a DC that cannot
#: write the confirmed record of an unlock keeps it armed.
UNLOCK_ARMED_QUALIFIER = "a DC that cannot write that record keeps it armed"


@pytest.mark.parametrize(
    "where",
    ["UNLOCK_CONFIRM_UNKNOWN_MESSAGE", "UNLOCK_ABORT_MESSAGE", "the plan tool description"],
)
def test_the_shipped_unlock_strings_scope_confirmed_to_a_record_that_was_written(
    where: str,
) -> None:
    """An unlock is recorded confirmed only when the DC can write that
    record; one that cannot keeps it armed.  No string Newton gives the
    agent says an unlock is confirmed once written, unqualified."""
    from newton_mcp.ad.write import apply as ad_apply

    if where == "the plan tool description":
        text = _tools()["newton_ad_plan_change"]
    else:
        text = _flat(getattr(ad_apply, where))
    assert "confirmed once written" not in text, where
    assert UNLOCK_ARMED_QUALIFIER in text, where


# ---- a refusal after the Samba timer was armed --------------------------------

#: A refusal after the Samba timer was armed (a move whose rename answered
#: 32, a target gone before the send) whose refused record cannot be written.
ARMED_REFUSAL_CLAUSE = (
    "a refusal after the undo timer was armed cancels the timer, and when its refused record"
    " cannot be written it answers with `unmarked`, and with `error` in place of `conflict`"
)


@pytest.mark.parametrize("relative", ["CHANGELOG.md", SPEC, SAMBA_README])
def test_the_docs_say_a_samba_refusal_after_arming_stops_the_timer(relative: str) -> None:
    text = _unreleased() if relative == "CHANGELOG.md" else _read(relative)
    text = " ".join(text.split())
    assert ARMED_REFUSAL_CLAUSE in text, relative


# ---- a new user whose objectGUID the DC did not record ------------------------

#: The exception to "a change that is not confirmed is put back": a user-create
#: whose add landed before its created objectGUID was recorded (a connection lost
#: between the two) is never deleted by its name, so it is left in place and its
#: record reads undo_failed.
USER_CREATE_EXCEPTION = "a new user whose objectGUID the DC did not record"


def _user_create_copies() -> dict[str, str]:
    from newton_mcp.ad.write import apply as ad_apply

    return {
        "APPLY_UNKNOWN_MESSAGE": _flat(ad_apply.APPLY_UNKNOWN_MESSAGE),
        "apply.py docstring": _flat(str(ad_apply.__doc__)),
        "apply tool": _tools()["newton_ad_apply_change"],
        "SKILL.md": _skill_ad_changes(),
        "README-1.0.md": _read("docs/release/README-1.0.md"),
        "CHANGELOG.md": _unreleased(),
        "DESIGN-1.4.md": _read("docs/proposals/ad/DESIGN-1.4.md"),
        # the abort tool may be called after an apply_unknown, and a DC error
        # may leave a new user armed with no objectGUID
        "ABORT_LOST_MESSAGE": _flat(ad_apply.ABORT_LOST_MESSAGE),
        "ABORT_TOOL_NOT_SENT_MESSAGE": _flat(ad_apply.ABORT_TOOL_NOT_SENT_MESSAGE),
        "abort tool": _tools()["newton_ad_abort_change"],
        "DC_ERROR_MESSAGE": _flat(ad_apply.DC_ERROR_MESSAGE),
        "DC_ERROR_NO_RECORD_MESSAGE": _flat(ad_apply.DC_ERROR_NO_RECORD_MESSAGE),
    }


@pytest.mark.parametrize(
    "name",
    ["APPLY_UNKNOWN_MESSAGE", "apply.py docstring", "apply tool", "SKILL.md",
     "README-1.0.md", "CHANGELOG.md", "DESIGN-1.4.md", "ABORT_LOST_MESSAGE",
     "ABORT_TOOL_NOT_SENT_MESSAGE", "abort tool", "DC_ERROR_MESSAGE",
     "DC_ERROR_NO_RECORD_MESSAGE"],
)
def test_every_put_back_promise_names_the_user_create_exception(name: str) -> None:
    """A lost apply of a user-create may leave a new user whose objectGUID
    was never recorded: both helpers leave it in place and record
    undo_failed.  Every copy of "a change that is not confirmed is put back
    by the DC" names that exception."""
    text = _user_create_copies()[name].replace("`", "")
    assert USER_CREATE_EXCEPTION in text, name
    clause = text[text.index(USER_CREATE_EXCEPTION):][:400]
    assert "in place" in clause, name
    assert "undo_failed" in clause, name


# ---- a pre-write code that carries unmarked -----------------------------------

#: A pre-write code is never refused on the code alone: a retry of an apply
#: the DC holds can get one from a helper that checks the token first.  It is
#: refused only when the DC has no record of the txid and the answer carries no
#: unmarked, or its record reads refused.
PRE_WRITE_CLAUSE = (
    "refused only when the DC holds no record of the transaction and the answer "
    "carries no unmarked, or its record says refused"
)


@pytest.mark.parametrize("name", ["apply tool", "SKILL.md", "CHANGELOG.md"])
def test_the_pre_write_codes_are_refused_only_when_the_dc_holds_no_record(name: str) -> None:
    text = " ".join({
        "apply tool": _tools()["newton_ad_apply_change"],
        "SKILL.md": _skill_ad_changes(),
        "CHANGELOG.md": _unreleased(),
    }[name].replace("`", "").split())
    assert PRE_WRITE_CLAUSE in text, name
    assert "on the code alone" not in text, name
    assert "which are refused unless the answer carries unmarked" not in text, name
    assert "which stay refused unless the answer carries unmarked" not in text, name


@pytest.mark.parametrize("name", ["CHANGELOG.md", "README-samba-write.md",
                                  "README-windows-write.md", "SPEC-1.4-REQUEST.md"])
def test_the_docs_say_the_replay_is_checked_before_the_token(name: str) -> None:
    """Both helpers look for a record of the txid before the token and the
    window, so a retry of an apply the DC holds answers replay."""
    path = {
        "CHANGELOG.md": REPO_ROOT / "CHANGELOG.md",
        "README-samba-write.md": REPO_ROOT / "mcp/newton_mcp/ad/collector/README-samba-write.md",
        "README-windows-write.md": REPO_ROOT / "mcp/newton_mcp/ad/collector/README-windows-write.md",
        "SPEC-1.4-REQUEST.md": REPO_ROOT / "docs/proposals/ad/SPEC-1.4-REQUEST.md",
    }[name]
    if not path.exists():
        pytest.skip(f"{name} is not in this layout")
    text = " ".join(path.read_text(encoding="utf-8").replace("`", "").split())
    assert "before the token and the approval window" in text, name


def test_the_changelog_says_an_unmarked_answer_whose_record_reads_refused_is_refused() -> None:
    text = _unreleased().replace("`", "")
    assert "never reports an answer that carries unmarked as nothing changed." not in text
    assert (
        "never reports an answer that carries unmarked as nothing changed unless its record"
        " of the change reads refused when Newton reads it back"
    ) in text
    # a replay is answered before any record exists, and apply.py reads it first
    assert "(a replay the DC answers stays a replay)" in text


@pytest.mark.parametrize("name", ["apply tool", "SKILL.md"])
def test_the_docs_say_an_abort_failed_with_not_sent_did_not_run(name: str) -> None:
    text = {"apply tool": _tools()["newton_ad_apply_change"],
            "SKILL.md": _skill_ad_changes()}[name].replace("`", "")
    assert "with the code not_sent the abort was not sent and did not run" in text, name


def test_the_state_comments_name_the_not_sent_confirm_and_abort() -> None:
    import inspect

    from newton_mcp.ad.write import apply as ad_apply

    source = " ".join(inspect.getsource(ad_apply).split())
    for state in ("STATE_CONFIRM_UNKNOWN", "STATE_ABORT_FAILED"):
        start = source.index(f"{state} = ")
        comment = source[source.rindex("STATE_", 0, start - 1):start]
        assert "not_sent" in comment, state
        # no record is read on that path: never "still armed"
        assert "still armed" not in comment, state
        assert "holds the change as it did" in comment, state


#: Nothing was sent, and no record was read: the not_sent confirm and abort
#: hedge, and the status says only that it was not sent and could not be read.
NOT_SENT_HEDGE = "the DC holds the change as it did"


def test_the_skill_never_says_a_not_sent_abort_leaves_the_change_armed() -> None:
    text = _skill_ad_changes().replace("`", "")
    assert "with the code not_sent the abort was not sent and did not run, and the change is still armed" not in text
    assert "with the code not_sent the abort was not sent and did not run, and " + NOT_SENT_HEDGE in text


def test_the_changelog_hedges_the_not_sent_confirm_and_abort() -> None:
    text = " ".join(_unreleased().replace("`", "").split())
    assert "says it was not sent: the change is still armed" not in text
    assert "carries the code not_sent: a status says it was not sent and could not be read" in text
    assert NOT_SENT_HEDGE in text
    assert "a change still armed is put back by the DC itself at or after its undo_at" in text


def test_the_apply_tool_names_the_not_sent_confirm() -> None:
    text = _tools()["newton_ad_apply_change"].replace("`", "")
    assert "confirm_unknown (every DC showed it, and the confirm may not have arrived; with the code not_sent it was not sent)" in text


# ---- a receipt that cannot be written -----------------------------------------

#: A final receipt write that raises on the Newton host never replaces the AD
#: result; the pending receipt before the send is the exception.
RECEIPT_ERROR_CLAUSE = "a final receipt that cannot be written is named in receipt_error"

#: Newton records the attempt before it sends the apply, and sends nothing
#: when it cannot.
PENDING_CLAUSE = (
    "before it sends the apply, Newton writes a pending receipt (apply_unknown) "
    "and syncs it to the disk; when that receipt cannot be written, nothing is "
    "sent and the apply is refused with code not_sent"
)
#: A pending receipt is an earlier apply until the DC says it holds nothing.
PENDING_RETRY_CLAUSE = (
    "a pending receipt is an earlier apply that may have reached the DC until "
    "the DC's record of the transaction answers not_found"
)


@pytest.mark.parametrize("name", ["apply tool", "SKILL.md", "CHANGELOG.md", "README-1.0.md"])
def test_the_docs_say_a_receipt_that_cannot_be_written_is_named_in_receipt_error(
    name: str,
) -> None:
    text = {
        "apply tool": _tools()["newton_ad_apply_change"],
        "SKILL.md": _skill_ad_changes(),
        "CHANGELOG.md": _unreleased(),
        "README-1.0.md": _read("docs/release/README-1.0.md"),
    }[name].replace("`", "")
    assert RECEIPT_ERROR_CLAUSE in text, name
    assert PENDING_CLAUSE in text, name
    assert PENDING_RETRY_CLAUSE in text, name
    assert "a replay whose check for the earlier receipt fails" not in text, name


# ---- a torn Windows generation ------------------------------------------------

#: A Windows generation whose write failed after its file was made stays on the
#: disk (the store has no Delete right); a reader takes the highest generation
#: that can be read and parses, and a generation whose read throws stops it.
TORN_GENERATION_CLAUSE = (
    "the current record is the highest generation that can be read and parses; "
    "a generation that cannot be read stops the reader"
)


@pytest.mark.parametrize("relative", ["CHANGELOG.md", SPEC, WINDOWS_README])
def test_the_docs_say_a_torn_windows_generation_never_hides_the_record(relative: str) -> None:
    text = " ".join((_unreleased() if relative == "CHANGELOG.md" else _read(relative)).split())
    text = text.replace("`", "")
    assert TORN_GENERATION_CLAUSE in text, relative
    assert "the highest generation that parses" not in text, relative
    if relative == SPEC:
        assert "The file with the highest n is the current record." not in text
        # the writers that read the current record first are readers too
        for writer in ("a state write", "the mark of an answered write",
                       "the unmarked check", "the apply"):
            assert writer in text[text.index("For a reader"):][:900], writer


#: A record whose read raises is never taken for absent, on either helper.
UNREADABLE_RECORD_CLAUSE = "a record that cannot be read is never taken for absent"


@pytest.mark.parametrize("relative", ["CHANGELOG.md", SAMBA_README, WINDOWS_README])
def test_the_docs_say_a_record_that_cannot_be_read_answers_error(relative: str) -> None:
    text = " ".join((_unreleased() if relative == "CHANGELOG.md" else _read(relative)).split())
    text = text.replace("`", "")
    assert UNREADABLE_RECORD_CLAUSE in text, relative
    clause = text[text.index(UNREADABLE_RECORD_CLAUSE):][:500]
    assert "error" in clause, relative
    assert "later pass" in clause, relative
    if relative != SAMBA_README:
        assert "a Windows store that cannot be listed is never taken for empty" in text, relative


# ---- a lost apply whose undo the DC already ran ------------------------------

#: A written change is normally armed after a lost apply, but both helpers run
#: the undo at once when they could not finish the apply after its write (a
#: read-back that raises on Samba, a failure after the write on Windows): the
#: record may already say undone or undo_failed.
ALREADY_UNDONE_HEDGE = "the DC may already have run the undo"


@pytest.mark.parametrize(
    "name",
    ["APPLY_UNKNOWN_MESSAGE", "apply.py docstring", "apply tool", "SKILL.md",
     "README-1.0.md", "CHANGELOG.md"],
)
def test_every_lost_apply_promise_says_the_undo_may_already_have_run(name: str) -> None:
    """After a lost apply, no copy says a written change is armed without
    the hedge: the DC may have put it back already, or recorded
    undo_failed."""
    text = _user_create_copies()[name].replace("`", "")
    assert "written is armed" not in text, name
    assert ALREADY_UNDONE_HEDGE in text, name
    clause = text[text.index(ALREADY_UNDONE_HEDGE):][:300]
    assert "undone" in clause, name
    assert "undo_failed" in clause, name


# ---- the root README's AD write sentence --------------------------------------


def test_the_root_readme_names_the_exceptions_to_the_dc_undo() -> None:
    """The source-tree README, when present, says the DC undoes a change
    whose confirm does not come: it names the same exceptions as the release
    README."""
    text = _flat((REPO_ROOT / "README.md").read_text(encoding="utf-8")).replace("`", "")
    marker = "undone by the DC itself when the confirm does not come"
    if (REPO_ROOT / "docs" / "release" / "README-1.0.md").exists():
        assert marker in text
    for start in [m.start() for m in re.finditer(re.escape(marker), text)]:
        clause = text[start:start + 400]
        assert "an unlock, which has no undo" in clause
        assert USER_CREATE_EXCEPTION in clause
        assert "in place" in clause
        assert "undo_failed" in clause


# ---- the password a plan record could not drop ---------------------------------


def _secret_drop_copies() -> dict[str, str]:
    from newton_mcp.ad.write import apply as ad_apply

    skill = _skill_ad_changes()
    return {
        "apply.py docstring": _flat(str(ad_apply.__doc__)),
        "SKILL.md": skill,
        "DESIGN-1.4.md": _read("docs/proposals/ad/DESIGN-1.4.md"),
    }


@pytest.mark.parametrize("name", ["apply.py docstring", "SKILL.md", "DESIGN-1.4.md"])
def test_every_password_drop_claim_names_the_secret_error(name: str) -> None:
    """The plan record drops a user-create's password after the apply sends
    it, unless the record cannot be rewritten: the result then names it in
    secret_error.  No copy says it is dropped without that exception."""
    text = _secret_drop_copies()[name].replace("`", "")
    assert "secret_error" in text, name


# ---- the confirm whose record Newton could not read ----------------------------


def _not_confirmed_copies() -> dict[str, str]:
    from newton_mcp.ad.write import apply as ad_apply

    source = (REPO_ROOT / "mcp" / "newton_mcp" / "ad" / "write" / "apply.py").read_text(
        encoding="utf-8")
    start = source.index("#: Every DC showed the after-image, and the DC answered the confirm")
    comment = _flat(source[start:source.index("STATE_NOT_CONFIRMED =", start)].replace("#:", " "))
    return {
        "NOT_CONFIRMED_NO_RECORD_MESSAGE": _flat(ad_apply.NOT_CONFIRMED_NO_RECORD_MESSAGE),
        "STATE_NOT_CONFIRMED comment": comment,
        "apply tool": _tools()["newton_ad_apply_change"],
        "SKILL.md": _skill_ad_changes(),
        "CHANGELOG.md": _read("CHANGELOG.md"),
        "README-1.0.md": _read("docs/release/README-1.0.md"),
    }


@pytest.mark.parametrize(
    "name",
    ["NOT_CONFIRMED_NO_RECORD_MESSAGE", "STATE_NOT_CONFIRMED comment", "apply tool",
     "SKILL.md", "CHANGELOG.md", "README-1.0.md"],
)
def test_no_copy_says_a_confirm_whose_record_was_not_read_was_not_recorded(name: str) -> None:
    """A DC can land the confirmed record and still answer error; when Newton
    then cannot read the record it does not know whether the confirm was
    recorded.  Every copy of the not_confirmed claim says so."""
    text = _not_confirmed_copies()[name].replace("`", "")
    assert "not_confirmed: the confirm was not recorded" not in text, name
    assert "otherwise the result is not_confirmed, the confirm was not recorded" not in text, name
    assert "does not know whether the confirm was recorded" in text, name


# ---- an apply while another change of the target is armed ----------------------

ARMED_GUARD = "while another armed record names the same target"
CLEANUP_BY_GUID = "only by its objectGUID"


@pytest.mark.parametrize(
    "relative",
    ["docs/proposals/ad/SPEC-1.4-REQUEST.md",
     "mcp/newton_mcp/ad/collector/README-samba-write.md",
     "mcp/newton_mcp/ad/collector/README-windows-write.md",
     "CHANGELOG.md"],
)
def test_the_docs_say_an_apply_is_refused_while_its_target_is_armed(relative: str) -> None:
    """Both helpers refuse an apply with conflict (and armed) while another
    armed record names the same target, so an armed undo never writes over a
    later confirmed change; a store that cannot be checked answers error."""
    text = (_unreleased() if relative == "CHANGELOG.md" else _read(relative)).replace("`", "")
    assert ARMED_GUARD in text, relative
    clause = text[text.index(ARMED_GUARD) - 300:][:900]
    assert "conflict" in clause, relative
    assert "armed" in clause, relative
    assert "error" in clause, relative


@pytest.mark.parametrize(
    "relative",
    ["docs/proposals/ad/SPEC-1.4-REQUEST.md",
     "mcp/newton_mcp/ad/collector/README-samba-write.md",
     "mcp/newton_mcp/ad/collector/README-windows-write.md",
     "CHANGELOG.md"],
)
def test_the_docs_say_the_apply_cleanup_deletes_a_new_user_only_by_its_guid(
    relative: str,
) -> None:
    """When the facts of a new user are missing right after the add, both
    helpers delete it only by its objectGUID; with no GUID they delete
    nothing and record undo_failed with the DN."""
    text = (_unreleased() if relative == "CHANGELOG.md" else _read(relative)).replace("`", "")
    assert CLEANUP_BY_GUID in text, relative
    clause = text[text.index(CLEANUP_BY_GUID):][:600]
    assert "undo_failed" in clause, relative
    assert "DN" in clause, relative


# ---- every shipped copy of the not_confirmed claim ----------------------------

#: The roots of the shipped docs and code; tests and private notes are not.
_SHIPPED_ROOTS = ("docs", "mcp/newton_mcp", "skills", "scripts", "device", "profiles", "commands")
_SHIPPED_SUFFIXES = (".md", ".py", ".ps1", ".toml", ".txt", "")
_NOT_SHIPPED_PARTS = {".git", ".agents", ".venv", "tests", "__pycache__", "research", "node_modules"}


def _shipped_files() -> list[Path]:
    found = [path for path in REPO_ROOT.glob("*.md") if path.is_file()]
    for root in _SHIPPED_ROOTS:
        base = REPO_ROOT / root
        if not base.is_dir():
            continue
        for path in base.rglob("*"):
            if not path.is_file() or path.suffix not in _SHIPPED_SUFFIXES:
                continue
            if _NOT_SHIPPED_PARTS.intersection(path.relative_to(REPO_ROOT).parts):
                continue
            found.append(path)
    return found


def test_no_shipped_file_says_a_refused_confirm_was_not_recorded() -> None:
    """A DC can land the confirmed record and still answer error, so a refused
    confirm never means the confirm was not recorded: no shipped doc or source
    says so (the release README is exported as the public README)."""
    files = _shipped_files()
    assert any(path.name == "README-1.0.md" for path in files) or (REPO_ROOT / "README.md").exists()
    bad = []
    for path in files:
        try:
            text = _flat(path.read_text(encoding="utf-8")).replace("`", "")
        except (UnicodeDecodeError, OSError):
            continue
        if "the confirm was not recorded" in text:
            bad.append(str(path.relative_to(REPO_ROOT)))
    assert bad == []


# ---- the armed undo of an old PDC, after the PDC role moved -------------------

#: The known limit every copy of the "once confirmed" claim names.
OLD_PDC_LIMIT = "while an earlier change of the same target is still armed on the old PDC"


@pytest.mark.parametrize(
    "name",
    ["SKILL.md", "CHANGELOG.md", "README-1.0.md", "ROADMAP.md", "ROADMAP-public.md"],
)
def test_every_once_confirmed_claim_names_the_old_pdc_limit(name: str) -> None:
    """The same-target guard reads only the store of the DC it runs on: a
    change applied on a new PDC while an earlier change of its target is still
    armed on the old one can be undone there.  Every copy of "once confirmed,
    Newton does not undo it" names that limit next to the claim."""
    text = {
        "SKILL.md": _skill_ad_changes(),
        "CHANGELOG.md": _unreleased(),
        "README-1.0.md": _readme_ad_line(),
        "ROADMAP.md": _roadmap_row("docs/ROADMAP.md"),
        "ROADMAP-public.md": _roadmap_row("docs/release/ROADMAP-public.md"),
    }[name]
    claim = text.replace("Once", "once").index("once confirmed, Newton does not undo it")
    assert OLD_PDC_LIMIT in text[claim:claim + 400], name


@pytest.mark.parametrize(
    "relative",
    ["docs/proposals/ad/SPEC-1.4-REQUEST.md",
     "mcp/newton_mcp/ad/collector/README-samba-write.md",
     "mcp/newton_mcp/ad/collector/README-windows-write.md",
     "CHANGELOG.md"],
)
def test_the_same_target_guard_docs_say_it_reads_only_its_own_dc(relative: str) -> None:
    text = (_unreleased() if relative == "CHANGELOG.md" else _read(relative)).replace("`", "")
    clause = text[text.index(ARMED_GUARD):][:1600]
    assert "only the store of the domain controller it runs on" in clause, relative
    if relative == "CHANGELOG.md":
        limits = text[text.index("### Known limits"):]
        assert OLD_PDC_LIMIT in limits, relative


#: Every wording of the claim that Newton does not undo a change.
_NO_UNDO_CLAIM = re.compile(
    r"\b(?:does not|doesn't|do not|don't|will not|won't|never) undo(?:es)?\b",
    re.IGNORECASE,
)


def _joined(path: Path) -> str:
    """The text of a shipped file on one line, with the string literals of a
    Python source joined (a description split over literals reads whole)."""
    text = _flat(path.read_text(encoding="utf-8")).replace("`", "")
    if path.suffix == ".py":
        text = re.sub(r'"\s*"', "", text)
    return text


def test_every_shipped_no_undo_claim_names_the_old_pdc_limit() -> None:
    """Every shipped copy of "once confirmed, Newton does not undo a change"
    in any wording (the docs, SKILL.md, the MCP tool descriptions of
    server.py) names the old-PDC known limit next to it: the claim holds on
    one PDC only.  A claim is a wording of "does not undo" with "confirm"
    just before it; the OpenWrt undo's "does not undo packages" and code
    comments are other claims."""
    files = _shipped_files()
    assert any(path.name == "server.py" for path in files)
    found: dict[str, int] = {}
    bad = []
    for path in files:
        try:
            text = _joined(path)
        except (UnicodeDecodeError, OSError):
            continue
        for match in _NO_UNDO_CLAIM.finditer(text):
            if "confirm" not in text[max(0, match.start() - 60):match.start()].lower():
                continue
            rel = path.relative_to(REPO_ROOT).as_posix()
            found[rel] = found.get(rel, 0) + 1
            if OLD_PDC_LIMIT not in text[match.start():match.start() + 400]:
                bad.append("%s: %s" % (rel, text[match.start():match.start() + 80]))
    # The copies each layout must hold: a tree with docs/release/ holds the
    # claim in docs/release/README-1.0.md and docs/release/ROADMAP-public.md;
    # a tree without it holds the claim in README.md.
    expected = {"SKILL.md": 1, "CHANGELOG.md": 1, "docs/ROADMAP.md": 1, "mcp/newton_mcp/server.py": 2}
    if (REPO_ROOT / "docs/release/README-1.0.md").is_file():
        expected.update({"docs/release/README-1.0.md": 1, "docs/release/ROADMAP-public.md": 1})
    else:
        expected["README.md"] = 1
    missing = {name: count for name, count in expected.items() if found.get(name, 0) < count}
    assert missing == {}, found
    assert bad == []


# ---- the GUID of a new user, read right after the add --------------------------


@pytest.mark.parametrize("relative", ["docs/proposals/ad/SPEC-1.4-REQUEST.md", "CHANGELOG.md"])
def test_the_new_user_guid_limit_names_both_lookups(relative: str) -> None:
    """Samba reads the new user's GUID at the planned DN, Windows by its
    sAMAccountName: the known limit names both."""
    text = (_unreleased() if relative == "CHANGELOG.md" else _read(relative)).replace("`", "")
    assert "planned DN right after the add" not in text, relative
    assert "by its sAMAccountName right after the add" in text, relative


def test_the_windows_readme_names_the_generation_files_of_the_store() -> None:
    text = _read("mcp/newton_mcp/ad/collector/README-windows-write.md").replace("`", "")
    assert "one <txid>.json per change" not in text
    assert "one <txid>.<generation>.json per state of a change (append-only), never deleted" in text


# ---- the DN values a write still sends ----------------------------------------


def test_the_changelog_guid_claim_names_the_dn_values_a_write_still_sends() -> None:
    """The member value of a membership, the new parent of a move and the
    parent of a new user are DNs read just before the write, so the claim
    that a write never lands on an account somebody made at a DN is
    qualified, and the known limit says what the undo then records."""
    text = " ".join(_unreleased().replace("`", "").split())
    claim = "so a write never lands on an account somebody made at that DN after moving Newton's away"
    assert claim in text
    tail = text[text.index(claim):][:400]
    assert "apart from the three DN values named in the known limits" in tail
    every = text[text.index("Every delete, modify and rename the helpers send"):][:500]
    assert "the machine account quota on Samba is written on the domain head by its DN" in every
    limits = text[text.index("### Known limits"):]
    limit = limits[limits.index("three names in it are still DNs read just before"):][:900]
    assert "the undo of that membership, which matches the member by GUID" in limit
    assert "records undone while the other account stays in the group" in limit


@pytest.mark.parametrize("readme", ["README-samba-write.md", "README-windows-write.md"])
def test_each_helper_readme_names_the_dn_values_a_write_still_sends(readme: str) -> None:
    """Each helper README says what the CHANGELOG says: the object a write
    names by GUID is never somebody else's account, but three names inside a
    write are DNs read just before it, and the membership undo then records
    undone while the other account stays in the group."""
    path = REPO_ROOT / "mcp" / "newton_mcp" / "ad" / "collector" / readme
    text = " ".join(path.read_text(encoding="utf-8").replace("`", "").split())
    assert "a write never lands on an account" not in text
    assert "the object written is never an account somebody made at that DN" in text
    assert ("the member value of a membership change, the new parent of a move and the parent of a "
            "new user") in text
    assert "records undone while the other account stays in the group" in text
    # The GUID of a user Newton creates is read right after the add, so an
    # account replacing it in that moment is the one recorded.
    assert "read right after the add" in text
