"""Owner-facing claims in the READMEs, SECURITY.md, SKILL.md and the lab
example file, each tied to the fact it states.

Every claim here was found stale or too wide: the release named in the
README and in SKILL.md, the README badge and banner, the Active Directory
work that is merged on main, the router's own expiry check (installed mode
only), the scenario counts, the router program the lab proof is of, the
number of guided questions, a test-count table that said "at this commit",
the approval lockout (the dialog only), the SECURITY.md scope and undo
claim, and the lab example's header about lab/lab.toml.

The facts are read from the tree (CHANGELOG headings, mcp/pyproject.toml,
the router program, the scenario folders, the AD catalogue, the guided
questions), so a later change that moves a fact makes the claim fail here.

The release build renames docs/release/README-1.0.md to README.md and drops
the dev README.  In that tree the release-README tests read README.md and
the dev-README tests are skipped.
"""

import re
import subprocess
from pathlib import Path
from urllib.parse import unquote

import pytest

REPO = Path(__file__).resolve().parents[2]
RELEASE_SRC = REPO / "docs/release/README-1.0.md"
PRIVATE = RELEASE_SRC.exists()
DEV_README = REPO / "README.md"
RELEASE_README = RELEASE_SRC if PRIVATE else REPO / "README.md"
SKILL = REPO / "SKILL.md"
SECURITY = REPO / "SECURITY.md"
CHANGELOG = REPO / "CHANGELOG.md"
PYPROJECT = REPO / "mcp/pyproject.toml"
ROUTER = REPO / "device/openwrt/newton-router/newton-router"
LAB_EXAMPLE = REPO / "lab/lab.example.toml"
SCRUB_RULES = REPO / "scripts/release-scrub.toml"

dev_only = pytest.mark.skipif(not PRIVATE, reason="the dev README is not in the release build")

WORDS = {
    10: "ten", 11: "eleven", 12: "twelve", 13: "thirteen", 14: "fourteen",
    15: "fifteen", 16: "sixteen", 17: "seventeen", 18: "eighteen",
}


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _section(text: str, start: str, end: str) -> str:
    i = text.index(start)
    return text[i:text.index(end, i)]


def _lines_with(text: str, needle: str) -> list[str]:
    found = [line for line in text.splitlines() if needle in line]
    assert found, needle
    return found


def _latest_release() -> str:
    m = re.search(r"^## \[(\d+\.\d+\.\d+)\]", _text(CHANGELOG), re.M)
    assert m, "no released version heading in CHANGELOG.md"
    return m.group(1)


def _package_version() -> str:
    m = re.search(r'^version = "([^"]+)"', _text(PYPROJECT), re.M)
    assert m
    return m.group(1)


def _router_version() -> str:
    m = re.search(r"hello %s api=1 version=(\d+\.\d+\.\d+) ", _text(ROUTER))
    assert m
    return m.group(1)


def _scenario_count(folder: str) -> int:
    return len(list((REPO / folder).glob("*.toml")))


# ---- the release, the badge, the banner, the AD work on main ----------------------------


def test_the_skill_frontmatter_names_the_released_version():
    """SKILL.md's frontmatter version is the latest release and the package version."""
    m = re.search(r"^version: (\S+)$", _text(SKILL), re.M)
    assert m
    assert m.group(1) == _latest_release() == _package_version()


@dev_only
def test_the_readme_status_names_the_latest_release():
    status = _section(_text(DEV_README), "## Status", "### Test counts")
    assert f"Newton {_latest_release()} is released" in status, status[:300]


@dev_only
def test_the_readme_badge_names_the_release_not_1_0_in_progress():
    """Both the alt text and the badge image (the shields.io URL) say it."""
    line = _lines_with(_text(DEV_README), "img.shields.io/badge/Status")[0]
    m = re.search(r"\[!\[([^\]]*)\]\((https://img\.shields\.io/badge/Status[^)]*)\)", line)
    assert m, line
    for part in (m.group(1), unquote(m.group(2))):
        assert "1.0 in progress" not in part, part
        assert _latest_release() in part, part


@dev_only
def test_the_in_progress_banner_is_dated_no_earlier_than_its_items():
    status = _section(_text(DEV_README), "## Status", "### Test counts")
    m = re.search(r"In progress \((\d{4}-\d{2}-\d{2})\):", status)
    assert m, status
    block = status[m.end():status.index("Proven in the virtual lab")]
    dates = re.findall(r"\d{4}-\d{2}-\d{2}", block)
    assert dates, block
    assert max(dates) <= m.group(1), (m.group(1), dates)


@dev_only
def test_the_readme_status_counts_the_ad_checks_merged_on_main():
    from newton_mcp.ad import catalogue

    status = _section(_text(DEV_README), "## Status", "### Test counts")
    assert f"{len(catalogue.CHECKS)} checks" in status, status
    assert "on a branch, not released" not in status, status
    for line in _lines_with(status, "Active Directory audit (1.3"):
        assert "merged on main" in line, line


@dev_only
def test_the_router_expiry_check_is_scoped_to_the_installed_router():
    """Only an installed OpenWrt router checks the approval's expiry itself;
    in the no-install mode and on other vendors only the Newton host does."""
    for line in _lines_with(_text(DEV_README), "by its own clock"):
        assert "installed OpenWrt router" in line, line
        assert "only the Newton host" in line, line


# ---- scenario counts and the router program the proofs are of -----------------------------


LAB_GROUPS = ["lab/scenarios", "lab/scenarios/openwrt", "lab/scenarios/everyday",
              "lab/scenarios/dualwan", "lab/scenarios/tiers"]


@dev_only
def test_the_readme_scenario_counts_match_the_tree():
    text = _text(DEV_README)
    line = _lines_with(text, "**Scenarios**")[0]
    total = 0
    for folder in LAB_GROUPS:
        n = _scenario_count(folder)
        total += n
        assert f"{n} in `{folder}/`" in line, (folder, n, line)
    pulsar = _scenario_count("lab/scenarios-pulsar")
    assert f"({total} in total, in {len(LAB_GROUPS)} groups)" in line, (total, line)
    assert f"plus {pulsar} for Pulsar" in line, (pulsar, line)
    assert f"{total} virtual-lab scenarios" in text
    assert f"{pulsar} scenarios for the real router" in text


@dev_only
def test_the_pulsar_run_says_what_it_covered():
    """The one full Pulsar run (2026-10-23) covered 97 scenarios on router
    program 1.1.0; the folder holds more now, so "All N" must be the
    folder's count or not be said."""
    text = _text(DEV_README)
    pulsar = _scenario_count("lab/scenarios-pulsar")
    for m in re.finditer(r"All (\d+) scenarios in `lab/scenarios-pulsar/`", text):
        assert int(m.group(1)) == pulsar, m.group(0)
    run = _lines_with(text, "(2026-10-23)")[0]
    assert "router program 1.1.0" in run, run


@dev_only
def test_the_virtual_lab_router_line_names_the_current_program():
    line = _lines_with(_text(DEV_README), "in the lab snapshot `baseline-newton-")[0]
    current = _router_version()
    snap = re.search(r'^snapshot = "(baseline-newton-[0-9-]+)"', _text(LAB_EXAMPLE), re.M)
    assert snap
    assert current in line, (current, line)
    assert snap.group(1) in line, (snap.group(1), line)


def test_the_skill_names_the_router_program_of_the_pulsar_run():
    for line in _lines_with(_text(SKILL), "Pulsar scenarios on a real router"):
        assert "router program 1.1.0" in line, line


# ---- the guided interview ---------------------------------------------------------------


@dev_only
def test_the_readme_counts_the_guided_questions():
    from newton_mcp import guided

    word = WORDS[len(guided.QUESTIONS)]
    line = _lines_with(_text(DEV_README), "interview questions")[0]
    assert f"asks {word} interview questions" in line, line


# ---- test counts are dated, not "at this commit" -----------------------------------------


@dev_only
def test_the_readme_test_counts_are_dated_not_at_this_commit():
    text = _text(DEV_README)
    assert "at this commit" not in text
    m = re.search(r"### Test counts as of (\d{4}-\d{2}-\d{2})", text)
    assert m
    table = text[m.end():text.index("## Quickstart")]
    assert f"passed on {m.group(1)}" in table, table[:300]


def test_the_release_readme_states_no_moving_ad_test_count():
    """A count of the AD tests on main is stale at the next commit."""
    text = _text(RELEASE_README)
    assert not re.search(r"holds [\d,]+ Active Directory tests", text)


# ---- the approval lockout is the dialog's ------------------------------------------------


def test_the_release_readme_scopes_the_lockout_to_the_dialog():
    """The terminal newton-approve fallback for a router change counts no
    wrong answers, ignores a lock and has no 1.5 s minimum."""
    text = _text(RELEASE_README)
    lines = [line for line in text.splitlines()
             if "wrong" in line and "lock approvals" in line]
    assert len(lines) == 2, lines
    for line in lines:
        assert "in the approval dialog" in line, line
        assert "counts no wrong answers" in line, line
    dwell = _lines_with(text, "under 1.5 s")[0]
    assert "in the dialog" in dwell, dwell
    assert "no minimum time" in dwell, dwell


# ---- SECURITY.md scope and undo claim ----------------------------------------------------


SECURITY_SCOPE = [
    "mcp/newton_mcp/ad/write/",
    "mcp/newton_mcp/ad/collector/write.ps1",
    "mcp/newton_mcp/ad/collector/newton-ad-samba-write",
    "scripts/newton-ad-setup",
    "mcp/newton_mcp/enrol.py",
    "scripts/newton-vantage-setup",
    "scripts/newton-vantage-run",
    "scripts/newton-vantage-check",
    "scripts/newton-serial.py",
]


def test_security_scope_names_the_ad_enrol_vantage_and_serial_code():
    scope = _section(_text(SECURITY), "## In scope", "## Out of scope")
    for path in SECURITY_SCOPE:
        assert (REPO / path).exists(), path
        assert f"`{path}`" in scope, path


def test_security_undo_claim_names_its_exceptions():
    text = _text(SECURITY)
    assert "Every write arms an undo timer on the router first." not in text
    model = _section(text, "## Security model in brief", "## Known limits")
    undo = _lines_with(model, "arms an undo")[0]
    assert "unlock" in undo, undo
    assert "newton-serial.py" in undo, undo
    limits = _section(text, "## Known limits", "## Supported versions")
    ad = _lines_with(limits, "Active Directory")[0]
    for needle in ("unlock", "objectGUID", "undo_failed", "CHANGELOG.md"):
        assert needle in ad, (needle, ad)


# ---- the lab example's header about lab/lab.toml -----------------------------------------


def test_the_lab_example_header_says_where_lab_toml_is_kept():
    header = _text(LAB_EXAMPLE).split("\n\n", 1)[0]
    assert "not part of this repository" not in header, header
    assert "kept out of every published copy" in header, header
    if SCRUB_RULES.exists():
        tracked = subprocess.run(
            ["git", "-C", str(REPO), "ls-files", "--error-unmatch", "lab/lab.toml"],
            capture_output=True, text=True, check=False,
        )
        if tracked.returncode == 0:
            assert '"lab/lab.toml",' in _text(SCRUB_RULES)


# ---- where lab/lab.toml lives, in every doc that says it -----------------------

LAB_TOML_DOCS = [LAB_EXAMPLE, REPO / "lab/scenarios-pulsar/README.md", REPO / "docs/TESTING-METHOD.md"]


@pytest.mark.parametrize("path", LAB_TOML_DOCS, ids=lambda p: p.name)
def test_no_doc_says_lab_toml_is_not_in_the_repository(path):
    flat = " ".join(re.sub(r"^\s*#\s?", "", _text(path), flags=re.M).split())
    assert not re.search(r"not (?:part of|in) (?:this|the) repository", flat), path.name
    assert "kept out of every published copy" in flat, path.name


# ---- the router's own approval check is a prod-profile check -------------------

ROUTER_CHECK_CLAIMS = [
    (RELEASE_README, "the router itself checks the approval"),
    (RELEASE_README, "the router program checks it again"),
    (SECURITY, "the router program checks it again on the device"),
]
if PRIVATE:
    ROUTER_CHECK_CLAIMS += [
        (DEV_README, "the router itself checks the approval"),
        (DEV_README, "by its own clock"),
    ]


def test_the_router_side_approval_check_names_the_profile():
    """cmd_apply checks the token only on a prod-profile router or for a plan
    with leash codes; a router set to lab skips it (newton-router cmd_apply)."""
    router = _text(ROUTER)
    assert 'if [ "$profile" = prod ] || [ "$lrc" -ne 1 ]; then' in router
    for path, needle in ROUTER_CHECK_CLAIMS:
        for line in _lines_with(_text(path), needle):
            assert "router set to lab" in line, (path.name, line)
            assert "only the Newton host checks" in line, (path.name, line)


# ---- every approval exception is named, and the AD gate is its own -------------


@dev_only
def test_the_approval_gate_bullet_names_both_exceptions_and_ad():
    line = _lines_with(_text(DEV_README), "Approval gate in code.")[0]
    assert "The one exception" not in line, line
    assert "scoped grant" in line, line
    assert "lab carve-out" in line, line
    assert "newton-approve ad-change" in line, line


def test_the_release_readme_chat_yes_names_the_grant():
    for line in _lines_with(_text(RELEASE_README), "said yes in the chat"):
        assert "Outside a scoped grant" in line, line
