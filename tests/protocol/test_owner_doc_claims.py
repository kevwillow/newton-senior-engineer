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
def test_the_readme_status_counts_the_ad_checks_released_in_1_4_0():
    from newton_mcp.ad import catalogue

    status = _section(_text(DEV_README), "## Status", "### Test counts")
    assert f"{len(catalogue.CHECKS)} checks" in status, status
    assert "on a branch, not released" not in status, status
    assert "not yet in a release" not in status, status
    for line in _lines_with(status, "Active Directory audit (1.3"):
        assert "1.4.0 added" in line, line


@dev_only
def test_the_router_expiry_check_is_scoped_to_the_installed_router():
    """Only an installed OpenWrt router checks the approval's expiry itself;
    in the no-install mode and on other vendors only the Newton host does."""
    for line in _lines_with(_text(DEV_README), "by its own clock"):
        assert "installed OpenWrt router" in line, line
        assert "only the Newton host" in line, line


# ---- scenario counts and the router program the proofs are of -----------------------------


LAB_GROUPS = ["lab/scenarios", "lab/scenarios/openwrt", "lab/scenarios/everyday",
              "lab/scenarios/dualwan", "lab/scenarios/tiers",
              "lab/scenarios/recipes"]


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


# ---- owner-doc drift: clients, token check, reboot, Python, bootstrap id, WAN cost, TOTP --------

INSTALL_DOC = REPO / "docs/INSTALL.md"
SETUP_DOC = REPO / "SETUP.md"
ROADMAP_DOC = REPO / "docs/ROADMAP.md"
BOOTSTRAP = REPO / "scripts/newton-bootstrap"
INSTALLER_SRC = REPO / "scripts/newton-install"
WAN_HEALTH = REPO / "scripts/newton-wan-health.sh"
READMES = [RELEASE_README] + ([DEV_README] if PRIVATE else [])


def _flat(path: Path) -> str:
    return " ".join(_text(path).split())


@pytest.mark.parametrize("path", READMES + [INSTALL_DOC, ROADMAP_DOC], ids=lambda p: str(p.relative_to(REPO)))
def test_no_doc_lists_claude_desktop_as_a_working_client(path):
    """docs/SETUP-CLIENTS.md says Claude Desktop cannot start the
    server; every other line that names it says it is not supported."""
    clients = _flat(REPO / "docs/SETUP-CLIENTS.md")
    assert "Claude Desktop is not supported" in clients
    for line in _text(path).splitlines():
        if "Claude Desktop" in line:
            assert "not supported" in line, (path.name, line)


def test_release_readme_security_model_names_the_lab_profile_skip():
    """the router checks the token again only on a prod-profile router
    or for a change Newton always asks about (newton-router cmd_apply)."""
    for line in _lines_with(_text(RELEASE_README), "checks it a second time on the device"):
        assert "router set to lab" in line, line
        assert "only the Newton host checks" in line, line


def test_skill_token_expiry_line_names_the_lab_profile_skip():
    """SKILL.md's 'the router refuses a token after its expiry' holds
    only where the router checks the token at all."""
    for line in _lines_with(_text(SKILL), "refuses a token after its expiry"):
        assert "router set to lab" in line, line


@pytest.mark.parametrize("path", READMES, ids=lambda p: str(p.relative_to(REPO)))
def test_readme_says_a_lab_router_still_refuses_changed_settings(path):
    """cmd_apply checks the base, diff and probes on every profile and
    skips only the token check on a lab router."""
    router = _text(ROUTER)
    assert '[ "$base" = "$base_sealed" ] || fail stale-base 3' in router
    assert '[ "$diff" = "$diff_sealed" ] || fail plan-changed 3 diff' in router
    assert '[ "$psha" = "$psha_sealed" ] || fail plan-changed 3 probes' in router
    line = _lines_with(_text(path), "Your approval is bound to the exact change")[0]
    assert "on every profile" in line, line
    assert "skips only the approval-token check" in line, line


def test_security_md_names_the_routeros_undo_reboot():
    """the RouterOS (CHR) undo loads a saved backup, which reboots."""
    flat = _flat(SECURITY)
    assert "No MCP tool runs arbitrary commands, reboots" not in flat
    assert "the only reboot is the RouterOS (CHR) undo" in flat


@pytest.mark.parametrize("path", READMES, ids=lambda p: str(p.relative_to(REPO)))
def test_readme_prerequisites_name_the_python_range(path):
    """newton-install accepts Python 3.11 to 3.14 only."""
    assert "Newton needs Python 3.11 to 3.14" in _text(INSTALLER_SRC)
    flat = _flat(path)
    assert "Python 3 with" not in flat
    assert "system Python 3 with" not in flat
    assert "Python 3.11 to 3.14" in flat, path.name
    assert "Python-3.11%2B" not in flat


@pytest.mark.parametrize("path", [RELEASE_README, SKILL, INSTALL_DOC, SETUP_DOC],
                         ids=lambda p: str(p.relative_to(REPO)))
def test_bootstrap_docs_ask_for_the_full_id(path):
    """newton-bootstrap's install and self-update ask for the full
    40-hex id, as the first install does."""
    boot = _text(BOOTSTRAP)
    assert '[[ $conf == "install $id" ]]' in boot
    assert '[[ $conf == "update $id" ]]' in boot
    flat = _flat(path)
    assert "first 12 hex characters of the id" not in flat, path.name
    assert "first 12 hex digits" not in flat, path.name
    assert "first 12 hex characters" not in flat, path.name


@pytest.mark.parametrize("path", [SETUP_DOC, SKILL], ids=lambda p: p.name)
def test_wan_health_docs_name_the_probe_cost(path):
    """every round pings each WAN, a metered backup too."""
    assert 'ping -I "$pi_dev" -c 1' in _text(WAN_HEALTH)
    flat = _flat(path)
    assert "metered" in flat, path.name
    assert "MB a month" in flat, path.name


def test_install_doc_offers_the_authenticator_on_no_install_too():
    """newton-enrol totp adds the authenticator in either mode (SETUP.md 7f)."""
    flat = _flat(INSTALL_DOC)
    assert "authenticator app belongs to the installed mode" not in flat
    assert "(installed mode only)" not in flat
    step = _section(_text(INSTALL_DOC), "**7f.**", "**7g.**")
    assert "On a no-install router" in step
    assert "newton-enrol totp router1" in " ".join(step.split()[:80])


# ---- owner-doc claims, continued ----

OWRT_CHANGE = REPO / "scripts/owrt-change.sh"


@pytest.mark.parametrize("path", READMES, ids=lambda p: str(p.relative_to(REPO)))
def test_readme_hold_window_is_the_timeout_minus_15_s(path):
    """owrt-change.sh ends the hold 15 s before the plan's timeout
    (deadline = SECONDS + T - 15), as SKILL.md says."""
    assert "deadline=$((SECONDS + T - 15))" in _text(OWRT_CHANGE)
    assert "the hold ends at `timeout_s` minus 15 s" in _flat(SKILL)
    for line in _lines_with(_text(path), "The hold window is"):
        assert "The hold window is the plan's timeout minus 15 s" in line, line


def test_release_readme_evidence_ticks_only_the_client_that_was_run():
    """no run with Codex or OpenCode is recorded
    (docs/SETUP-CLIENTS.md 'Not confirmed'); a tick line that names them
    says they were not run."""
    clients = _flat(REPO / "docs/SETUP-CLIENTS.md")
    assert "was not tested here" in clients
    evidence = _section(_text(RELEASE_README), "**Lab and test evidence**", "### ")
    for line in evidence.splitlines():
        if line.startswith("- ✓") and ("Codex" in line or "OpenCode" in line):
            assert "not run" in line, line


def test_setup_clients_names_claude_desktop_only_as_not_supported():
    """outside its own section, every line of SETUP-CLIENTS.md
    that names Claude Desktop says it is not supported."""
    text = _text(REPO / "docs/SETUP-CLIENTS.md")
    section = _section(text, "### Claude Desktop", "\n#")
    assert "Claude Desktop is not supported" in " ".join(section.split())
    rest = text.replace(section, "")
    for line in rest.splitlines():
        if "Claude Desktop" in line:
            assert "not supported" in line, line


def test_skill_ad_change_status_names_not_found():
    """the tool answers not_found too (server.py description)."""
    server = _text(REPO / "mcp/newton_mcp/server.py")
    assert "armed, confirmed, undone, undo_failed, refused or not_found" in " ".join(server.split())
    flat = _flat(SKILL)
    assert (
        "`newton_ad_change_status(device, plan_id)` shows `armed`, `confirmed`, `undone`, "
        "`undo_failed`, `refused` or `not_found`"
    ) in flat


SECURITY_SCOPE_R4 = [
    "scripts/newton-wan-health.sh",
    "scripts/newton-wan-health.init",
    "scripts/newton-scan",
    "scripts/newton-rules",
]


def test_security_scope_names_the_wan_health_scan_and_rules_code():
    """newton-wan-health.sh runs as root on the router, newton-scan
    on the vantage, newton-rules as the newton user."""
    scope = _section(_text(SECURITY), "## In scope", "## Out of scope")
    for path in SECURITY_SCOPE_R4:
        assert (REPO / path).exists(), path
        assert f"`{path}`" in scope, path


def test_security_md_places_every_script():
    """every file under scripts/ is named in scope or out of
    scope, so a reporter can tell (the scrub's own files are not in the
    public tree)."""
    import tomllib

    excluded = set(tomllib.loads(_text(SCRUB_RULES))["tree"]["exclude"]) if SCRUB_RULES.exists() else set()
    text = _text(SECURITY)
    for path in sorted((REPO / "scripts").iterdir()):
        rel = f"scripts/{path.name}"
        if not path.is_file() or rel in excluded:
            continue
        assert f"`{rel}`" in text, rel


BOOTSTRAP_OLDER_NOTE = (
    "A bootstrap installed by an earlier release asks for a 12-hex prefix of the id instead"
)


@pytest.mark.parametrize("path", [RELEASE_README, SKILL, INSTALL_DOC, SETUP_DOC],
                         ids=lambda p: str(p.relative_to(REPO)))
def test_bootstrap_docs_say_an_older_bootstrap_asks_for_12_hex_and_to_self_update(path):
    """--from-snapshot never replaces the bootstrap, so an
    existing install keeps the old prompt until its self-update."""
    assert "--from-snapshot never touches" in _text(INSTALLER_SRC)
    flat = _flat(path)
    assert BOOTSTRAP_OLDER_NOTE in flat, path.name
    assert "newton-bootstrap self-update <repo>" in flat, path.name


SKILL_SIZE_CAP = 100 * 1024


def test_skill_md_stays_under_its_size_cap():
    """SKILL.md loads whole on every trigger; a ceiling stops it
    growing without anyone deciding to.  Move detail to references/ before
    raising the cap."""
    size = len(SKILL.read_bytes())
    assert size <= SKILL_SIZE_CAP, size


def test_skill_description_scopes_the_broadest_triggers():
    """generic network questions load the skill only when the
    network is one Newton manages."""
    head = _text(SKILL).split("\n---\n", 1)[0]
    description = next(line for line in head.splitlines() if line.startswith("description:"))
    assert "'how fast is my internet' on a network Newton manages" in description
    assert "or network config on a Linux host" not in description
