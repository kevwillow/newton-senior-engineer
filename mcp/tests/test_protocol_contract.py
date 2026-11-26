"""The checker of the change protocol contract table.

``docs/design/13-CHANGE-PROTOCOL.md`` holds the contract: for every rule of
the change protocol and every change mode, the table names the tests that
prove the rule. This module reads that table and fails when the table and the
repository no longer agree:

* the header row is not the one of the contract,
* a rule row is missing, or the rows are not numbered 1 to 10,
* a mode cell is empty, or holds something that is neither test ids, an
  ``n/a`` with a reason, nor a gap,
* a cited test id names a file, a class or a function that is not there,
* a gap of the table has no bullet of its own, or a bullet names a gap the
  table does not use.

The checker is pure text and pure standard library: it reads the file names
and the ``def`` lines of the cited files, it never imports them.
"""

from __future__ import annotations

import re
from pathlib import Path

#: The repository root: this file lives in ``mcp/tests/``.
ROOT = Path(__file__).resolve().parents[2]

#: The document that holds the contract.
DOC = ROOT / "docs" / "design" / "13-CHANGE-PROTOCOL.md"

#: The markers of the table.
START = "<!-- contract-table:start -->"
END = "<!-- contract-table:end -->"

#: The header row of the table: the number, the rule and the six modes.
HEADER = (
    "#",
    "Rule",
    "OpenWrt installed",
    "OpenWrt no-install",
    "VyOS/Junos",
    "CHR",
    "AD write",
    "AD build",
)

#: The mode columns, in the order of the table.
MODES = HEADER[2:]

#: One test id in backticks: a path and a function, or a path, a class and a
#: function.
ID_RE = re.compile(r"^`([^`]+)`$")

#: A gap cell.
GAP_RE = re.compile(r"^gap G(\d+)$")

#: A bullet of the gaps list: the gap, the rule, the mode, what no test
#: proves and who closes it.
BULLET_RE = re.compile(
    r"^- G(\d+) \(rule (\d+), ([^)]+)\): (.+) Closed by: (.+)\.$"
)


# ---- reading the document ----------------------------------------------------


def _table_lines(text: str) -> list[str]:
    """The lines of the contract table, between the two markers."""
    if START not in text or END not in text:
        return []
    between = text.split(START, 1)[1].split(END, 1)[0]
    return [line for line in between.splitlines() if line.strip()]


def _cells(line: str) -> list[str]:
    """The cells of one table row."""
    stripped = line.strip()
    if not stripped.startswith("|"):
        return []
    return [part.strip() for part in stripped.split("|")[1:-1]]


def _gap_blocks(text: str) -> list[str]:
    """The raw bullet blocks of the gaps section, one block per gap."""
    if "## Gaps" not in text:
        return []
    after = text.split("## Gaps", 1)[1]
    blocks: list[str] = []
    current: list[str] = []
    for line in after.splitlines():
        if line.startswith("- "):
            if current:
                blocks.append("\n".join(current))
            current = [line]
        elif current and line.strip() and not line.startswith("#"):
            current.append(line)
        else:
            if current:
                blocks.append("\n".join(current))
                current = []
    if current:
        blocks.append("\n".join(current))
    return blocks


def _gap_bullets(text: str) -> list[str]:
    """The bullet blocks of the gaps section, one line each."""
    return [" ".join(block.split()) for block in _gap_blocks(text)]


# ---- reading the cited tests -------------------------------------------------


def _has_function(path: Path, name: str) -> bool:
    """True when the file holds a function (or an async function) of that name."""
    try:
        source = path.read_text(encoding="utf-8")
    except OSError:
        return False
    return bool(
        re.search(rf"^\s*(?:async\s+)?def\s+{re.escape(name)}\s*\(", source, re.M)
    )


def _has_class(path: Path, name: str) -> bool:
    """True when the file holds a class of that name."""
    try:
        source = path.read_text(encoding="utf-8")
    except OSError:
        return False
    return bool(re.search(rf"^\s*class\s+{re.escape(name)}\s*[:(]", source, re.M))


def _ids_of(cell: str) -> list[str] | None:
    """The test ids of a cell, or None when the cell is not a list of ids."""
    ids: list[str] = []
    for part in cell.split("<br>"):
        found = ID_RE.match(part.strip())
        if not found:
            return None
        ids.append(found.group(1))
    return ids


# ---- the checker -------------------------------------------------------------


def _id_problems(ident: str, row: int, mode: str, root: Path) -> list[str]:
    """The problems of one cited test id."""
    parts = ident.split("::")
    if len(parts) not in (2, 3):
        return [f"row {row}, {mode}: {ident} is not a test id"]
    relative = Path(parts[0])
    if relative.is_absolute() or ".." in relative.parts:
        return [f"row {row}, {mode}: {ident} names a path outside the repository"]
    path = root / relative
    if not path.is_file():
        return [
            f"row {row}, {mode}: {ident} names a file that is not in the "
            f"repository: {parts[0]}"
        ]
    if len(parts) == 3 and not _has_class(path, parts[1]):
        return [
            f"row {row}, {mode}: {ident} names a class {parts[1]} that "
            f"{parts[0]} does not have"
        ]
    if not _has_function(path, parts[-1]):
        return [
            f"row {row}, {mode}: {ident} names no function {parts[-1]} in {parts[0]}"
        ]
    return []


def check(text: str, root: Path) -> list[str]:
    """The problems of the contract table in ``text``.

    An empty list means the table is good: every rule has a row, every mode
    cell holds test ids, an ``n/a`` with a reason or a gap, every cited test
    exists, and every gap has a bullet of its own.
    """
    problems: list[str] = []
    gaps: list[int] = []

    if START not in text:
        problems.append(f"the table start marker {START} is missing")
    if END not in text:
        problems.append(f"the table end marker {END} is missing")
    if problems:
        return problems

    lines = _table_lines(text)
    if len(lines) < 2:
        problems.append("the table holds no rows")
        return problems

    header = _cells(lines[0])
    if header != list(HEADER):
        problems.append(f"the header row is {header}, not {list(HEADER)}")
    separator = _cells(lines[1])
    if not separator or not all(cell and set(cell) <= set("-:") for cell in separator):
        problems.append("the row under the header is not a separator row")

    rows = lines[2:]
    if len(rows) != 10:
        problems.append(f"the table has {len(rows)} data rows, not 10")
    for index, line in enumerate(rows, start=1):
        cells = _cells(line)
        if len(cells) != len(HEADER):
            problems.append(
                f"row {index}: the row has {len(cells)} cells, not {len(HEADER)}"
            )
            continue
        if cells[0] != str(index):
            problems.append(f"row {index}: the row is numbered {cells[0]!r}")
        if not cells[1]:
            problems.append(f"row {index}: the rule cell is empty")
        for column, mode in enumerate(MODES, start=2):
            cell = cells[column]
            if not cell:
                problems.append(f"row {index}, {mode}: the cell is empty")
                continue
            if cell.startswith("n/a"):
                reason = cell[3:]
                if not reason.startswith(":"):
                    problems.append(
                        f"row {index}, {mode}: the n/a cell has no reason: {cell!r}"
                    )
                elif not reason[1:].strip():
                    problems.append(f"row {index}, {mode}: the n/a cell has no reason")
                continue
            gap = GAP_RE.match(cell)
            if gap:
                gaps.append(int(gap.group(1)))
                continue
            ids = _ids_of(cell)
            if ids is None:
                problems.append(
                    f"row {index}, {mode}: the cell is neither test ids, an n/a "
                    f"reason nor a gap: {cell!r}"
                )
                continue
            for ident in ids:
                problems.extend(_id_problems(ident, index, mode, root))

    bullets: dict[int, str] = {}
    for bullet in _gap_bullets(text):
        found = BULLET_RE.match(bullet)
        if not found:
            problems.append(f"the gap bullet is not in the expected form: {bullet!r}")
            continue
        number = int(found.group(1))
        if number in bullets:
            problems.append(f"gap G{number} has more than one bullet")
        bullets[number] = bullet
    for number in sorted(set(gaps)):
        if number not in bullets:
            problems.append(f"gap G{number} has no bullet in the gaps section")
    for number in sorted(bullets):
        if number not in gaps:
            problems.append(
                f"the bullet of gap G{number} is not used in the table"
            )
    return problems


# ---- the tests ---------------------------------------------------------------


def _doc() -> str:
    """The text of the real contract document."""
    return DOC.read_text(encoding="utf-8")


def _first_id(text: str) -> str:
    """The first test id of the table."""
    for line in _table_lines(text):
        for cell in _cells(line)[2:]:
            found = re.search(r"`([^`]+::[^`]+)`", cell)
            if found:
                return found.group(1)
    raise AssertionError("the table holds no test id")


def _first_row(text: str) -> str:
    """The first data row of the table."""
    lines = _table_lines(text)
    assert len(lines) > 2, "the table holds no data row"
    return lines[2]


def _row_with_cell(text: str, cell: str) -> str:
    """The text of the table with the cell of the first data row replaced."""
    row = _first_row(text)
    cells = _cells(row)
    cells[2] = cell
    return text.replace(row.strip(), "| " + " | ".join(cells) + " |", 1)


def test_contract_doc_is_valid() -> None:
    """The real document passes the checker."""
    problems = check(_doc(), ROOT)
    assert problems == [], "\n".join(problems)


def test_a_renamed_cited_test_is_a_problem() -> None:
    """A cited function that was renamed is a problem that names the id."""
    text = _doc()
    ident = _first_id(text)
    parts = ident.split("::")
    renamed = "::".join(parts[:-1] + [parts[-1] + "_renamed"])
    broken = text.replace(f"`{ident}`", f"`{renamed}`", 1)
    assert broken != text, "the document does not cite that test"

    problems = check(broken, ROOT)

    assert problems, "the checker did not notice the renamed test"
    assert any(renamed in problem for problem in problems), problems


def test_a_cited_file_that_is_gone_is_a_problem() -> None:
    """A cited file that is not in the repository is a problem."""
    text = _doc()
    ident = _first_id(text)
    parts = ident.split("::")
    moved = "::".join(["mcp/tests/test_a_file_that_is_not_there.py"] + parts[1:])
    broken = text.replace(f"`{ident}`", f"`{moved}`", 1)
    assert broken != text, "the document does not cite that test"

    problems = check(broken, ROOT)

    assert problems, "the checker did not notice the missing file"
    assert any(moved in problem for problem in problems), problems


def test_an_empty_cell_is_a_problem() -> None:
    """A mode cell with nothing in it is a problem."""
    broken = _row_with_cell(_doc(), "")

    problems = check(broken, ROOT)

    assert problems, "the checker did not notice the empty cell"
    assert any("empty" in problem for problem in problems), problems


def test_a_missing_row_is_a_problem() -> None:
    """A table with nine data rows is a problem."""
    text = _doc()
    row = _table_lines(text)[-1]
    broken = text.replace(row + "\n", "", 1)
    assert broken != text, "the table has no last row"

    problems = check(broken, ROOT)

    assert problems, "the checker did not notice the missing row"
    assert any("data rows" in problem for problem in problems), problems


SYNTHETIC_BULLET = (
    "- G99 (rule 1, OpenWrt installed): a gap made up by this test. "
    "Closed by: the maintainer."
)


def _with_a_gap(text: str) -> tuple[str, str]:
    """The doc with one made-up gap: row 1's OpenWrt-installed cell becomes
    ``gap G99`` and the gaps section gets its bullet.  Returns the doc and
    the cell that was replaced.  The real doc may have no gap at all, so
    the gap tests build their own."""
    row = _first_row(text)
    cells = _cells(row)
    original = cells[2]
    cells[2] = "gap G99"
    new_row = "| " + " | ".join(cells) + " |"
    text = text.replace(row, new_row, 1)
    if "## Gaps" in text:
        head, tail = text.split("## Gaps", 1)
        text = head + "## Gaps\n\n" + SYNTHETIC_BULLET + "\n" + tail
    else:
        text = text.rstrip("\n") + "\n\n## Gaps\n\n" + SYNTHETIC_BULLET + "\n"
    return text, original


def test_the_made_up_gap_is_a_valid_doc() -> None:
    """The doc with the made-up gap passes: the gap tests below change one
    thing of a valid doc, so a problem they find is that one change."""
    text, _original = _with_a_gap(_doc())

    assert check(text, ROOT) == []


def test_a_gap_without_a_bullet_is_a_problem() -> None:
    """A gap of the table whose bullet is gone is a problem."""
    text, _original = _with_a_gap(_doc())
    broken = text.replace(SYNTHETIC_BULLET + "\n", "", 1)
    assert broken != text, "the bullet is not in the document"

    problems = check(broken, ROOT)

    assert problems, "the checker did not notice the missing bullet"
    assert any("has no bullet" in problem for problem in problems), problems


def test_an_na_cell_without_a_reason_is_a_problem() -> None:
    """An ``n/a`` cell with no reason is a problem."""
    broken = _row_with_cell(_doc(), "n/a:")

    problems = check(broken, ROOT)

    assert problems, "the checker did not notice the missing reason"
    assert any("reason" in problem for problem in problems), problems


def test_a_gap_bullet_without_a_gap_in_the_table_is_a_problem() -> None:
    """A bullet of a gap the table does not use is a problem."""
    text, original = _with_a_gap(_doc())
    broken = text.replace("| gap G99 |", f"| {original} |", 1)
    assert broken != text, "the made-up gap is not in the table"

    problems = check(broken, ROOT)

    assert problems, "the checker did not notice the orphan bullet"
    assert any("not used in the table" in problem for problem in problems), problems


def test_a_changed_header_row_is_a_problem() -> None:
    """A header row that is not the one of the contract is a problem."""
    broken = _doc().replace(
        "| # | Rule | OpenWrt installed |", "| # | Rule | OpenWrt |", 1
    )

    problems = check(broken, ROOT)

    assert problems, "the checker did not notice the changed header"
    assert any("header row" in problem for problem in problems), problems
