"""Tests for profiles/check.py.

Every failing-case test first proves, inside the same test, that the
unmutated copy passes (exit 0), so the failure can only come from the
mutation. Manifests and .uci files are copied/rebuilt in tmp_path; the
repo is never written to.
"""

import importlib.util
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROFILES = ROOT / "profiles"
REAL_MANIFEST = PROFILES / "openwrt" / "manifest.toml"
CTL = "OW-MGMT-03"  # a proven standard control with a small batch


REAL_TIERS_DOC = ROOT / "docs" / "research" / "profiles-tiers-25.12.md"
LAB_WORD = {"proven": "proven", "audit": "proven, audit only",
            "caveat": "proven with a caveat", "not-yet": "not yet"}


def synthetic_tiers_doc():
    """A tiers document in the format parse_tiers_doc reads, written from the
    unmutated manifest.  The real planning note is not part of this
    repository; this stands in for it, so the doc-versus-manifest checks
    still have something to compare a mutated manifest with."""
    controls = tomllib.loads(REAL_MANIFEST.read_text())["control"]

    def row(c, name=None):
        return (f"| {name or c['id']} | what | breaks | "
                f"{LAB_WORD[c['lab']]} | |")

    out = ["# tiers", "", "## At a glance", "", "Whole tiers, cumulative.", ""]
    plain = [c for c in controls if not c["step_up_of"] and not c["form_of"]
             and c["tier"] != "none"]
    cum = 0
    for tier in ("standard", "hardened", "lockdown"):
        cum += sum(1 for c in plain if c["tier"] == tier)
        out.append(f"| {tier.capitalize()} | {cum} | 0 | 0 | 0 |")
    n_opt = sum(1 for c in plain if c["tier"] == "opt-in")
    out += [f"| Opt-in extras | {n_opt} | 0 | 0 | 0 |", ""]
    for tier, head in (("standard", "Standard"), ("hardened", "Hardened"),
                       ("lockdown", "Lockdown"), ("opt-in", "Opt-in extras")):
        out += [f"## {head}", "", "| ID | a | b | Lab | n |", "|---|---|---|---|---|"]
        out += [row(c) for c in plain if c["tier"] == tier]
        for c in controls:
            if c["tier"] == tier and c["form_of"]:
                out.append(row(c, c["id"] + " (form)"))
        steps = [c for c in controls if c["tier"] == tier and c["step_up_of"]]
        if steps:
            out += ["", f"**Steps up in {head}** (same control)", "",
                    "| ID | a | b | Lab | n |", "|---|---|---|---|---|"]
            out += [row(c) for c in steps]
        out.append("")
    out += ["## Not in a tier yet", "", "### No scenario yet", "",
            "| ID | a | b | c | d |", "|---|---|---|---|---|"]
    out += [f"| {c['id']} | x | x | x | |" for c in controls
            if c["lab"] == "not-yet"]
    out.append("")
    for c in controls:
        if c["tier"] == "none":
            out += [f"- **No tier:** {c['id']}", ""]
    return "\n".join(out)


def tiers_doc_text():
    """The real tiers document when the tree has it, else the synthetic one."""
    if REAL_TIERS_DOC.is_file():
        return REAL_TIERS_DOC.read_text()
    return synthetic_tiers_doc()


def run_check(manifest, uci_dir, scenarios_dir=None):
    argv = [sys.executable, str(PROFILES / "check.py"),
            "--manifest", str(manifest), "--uci-dir", str(uci_dir)]
    if not REAL_TIERS_DOC.is_file():
        doc = Path(manifest).parent / "synthetic-tiers-doc.md"
        doc.write_text(synthetic_tiers_doc())
        argv += ["--tiers-doc", str(doc)]
    if scenarios_dir is not None:
        argv += ["--scenarios-dir", str(scenarios_dir)]
    return subprocess.run(
        argv,
        capture_output=True, text=True,
    )


def run_build(manifest, uci_dir):
    return subprocess.run(
        [sys.executable, str(PROFILES / "build.py"),
         "--manifest", str(manifest), "--out-dir", str(uci_dir)],
        capture_output=True, text=True,
    )


def baseline(tmp_path):
    """Unmutated copy of the real manifest + matching fresh .uci files,
    proven to pass check.py (exit 0)."""
    manifest = tmp_path / "manifest.toml"
    manifest.write_bytes(REAL_MANIFEST.read_bytes())
    uci = tmp_path / "uci"
    uci.mkdir()
    built = run_build(manifest, uci)
    assert built.returncode == 0, built.stderr
    ok = run_check(manifest, uci)
    assert ok.returncode == 0, ok.stdout + ok.stderr
    return manifest, uci


def block_list(text):
    return text.split("[[control]]")


def ctl_block(text, ctl_id):
    for part in block_list(text):
        if f"id = '{ctl_id}'" in part:
            return part
    raise AssertionError(f"control {ctl_id} not found in manifest")


def write_mutated(tmp_path, text, fn, rebuild_uci, uci):
    parts = block_list(text)
    idx = next(i for i, p in enumerate(parts) if f"id = '{CTL}'" in p)
    parts[idx] = fn(parts[idx])
    manifest = tmp_path / "mutated.toml"
    manifest.write_text("[[control]]".join(parts))
    if rebuild_uci:
        rebuilt = run_build(manifest, uci)
        assert rebuilt.returncode == 0, rebuilt.stderr
    return manifest


def write_control_mutation(tmp_path, text, control_id, tier, fn,
                           rebuild_uci, uci, name="mutated.toml"):
    parts = block_list(text)
    idx = next(i for i, part in enumerate(parts)
               if f"id = '{control_id}'" in part
               and f"tier = '{tier}'" in part)
    parts[idx] = fn(parts[idx])
    manifest = tmp_path / name
    manifest.write_text("[[control]]".join(parts))
    if rebuild_uci:
        rebuilt = run_build(manifest, uci)
        assert rebuilt.returncode == 0, rebuilt.stderr
    return manifest


def add_batch_line(block, line):
    return block.replace("batch = [\n", f'batch = [\n  "{line}",\n')


def lines_with(result, needle):
    return [line for line in result.stdout.splitlines() if needle in line]


def set_key(block, key, value):
    changed, count = re.subn(
        rf"(?ms)^{key} = (?:'''.*?'''|\[\n.*?\n\]|[^\n]*)$",
        lambda _match: f"{key} = {value}", block, count=1,
    )
    assert count == 1
    return changed


def test_check_passes_on_the_real_files():
    result = subprocess.run(
        [sys.executable, str(PROFILES / "check.py")],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "OK" in result.stdout


def test_missing_control(tmp_path):
    manifest, uci = baseline(tmp_path)
    parts = block_list(manifest.read_text())
    idx = next(i for i, p in enumerate(parts) if f"id = '{CTL}'" in p)
    del parts[idx]
    manifest.write_text("[[control]]".join(parts))
    rebuilt = run_build(manifest, uci)
    assert rebuilt.returncode == 0, rebuilt.stderr
    result = run_check(manifest, uci)
    assert result.returncode == 1
    assert lines_with(result, f"{CTL} standard: missing from the manifest")


def test_wrong_tier_count(tmp_path):
    manifest, uci = baseline(tmp_path)
    mutated = write_mutated(
        tmp_path, manifest.read_text(),
        lambda b: b.replace("tier = 'standard'", "tier = 'hardened'"),
        rebuild_uci=True, uci=uci,
    )
    result = run_check(mutated, uci)
    assert result.returncode == 1
    assert lines_with(result, "tier count standard")


def test_batch_without_check(tmp_path):
    manifest, uci = baseline(tmp_path)
    mutated = write_mutated(
        tmp_path, manifest.read_text(),
        lambda b: re.sub(r"check = .*?\nexpect =", "check = ''\nexpect =",
                         b, count=1, flags=re.S),
        rebuild_uci=True, uci=uci,
    )
    result = run_check(mutated, uci)
    assert result.returncode == 1
    assert lines_with(result, f"{CTL} standard: batch has no check")


def test_hard_coded_radio_name(tmp_path):
    manifest, uci = baseline(tmp_path)
    mutated = write_mutated(
        tmp_path, manifest.read_text(),
        lambda b: add_batch_line(b, "set wireless.radio0.disabled='1'"),
        rebuild_uci=True, uci=uci,
    )
    result = run_check(mutated, uci)
    assert result.returncode == 1
    hits = lines_with(result, "hard-codes a physical or radio name")
    assert hits and any("radio0" in line for line in hits)


def test_stale_uci_file(tmp_path):
    manifest, uci = baseline(tmp_path)  # uci matches the manifest: passes
    mutated = write_mutated(
        tmp_path, manifest.read_text(),
        lambda b: add_batch_line(b, "set system.@system[0].timezone='UTC'"),
        rebuild_uci=False, uci=uci,  # uci dir stays stale on purpose
    )
    result = run_check(mutated, uci)
    assert result.returncode == 1
    assert lines_with(result, "stale")


def test_lab_word_differs_from_tier_doc(tmp_path):
    manifest, uci = baseline(tmp_path)
    mutated = write_mutated(
        tmp_path, manifest.read_text(),
        lambda b: b.replace("lab = 'proven'", "lab = 'caveat'"),
        rebuild_uci=True, uci=uci,
    )
    result = run_check(mutated, uci)
    assert result.returncode == 1
    hits = lines_with(result, "lab is caveat, the tier doc says proven")
    assert hits and any(CTL in line for line in hits)


def test_missing_scenario_file(tmp_path):
    manifest, uci = baseline(tmp_path)
    mutated = write_mutated(
        tmp_path, manifest.read_text(),
        lambda b: b.replace(
            "scenario = 'ow-mgmt-03-uhttpd-redirect-https.toml'",
            "scenario = 'ow-mgmt-03-no-such-file.toml'",
        ),
        rebuild_uci=True, uci=uci,
    )
    result = run_check(mutated, uci)
    assert result.returncode == 1
    hits = lines_with(result, "scenario file ow-mgmt-03-no-such-file.toml")
    assert hits and any(CTL in line for line in hits)


def test_hard_coded_lan_device_in_batch(tmp_path):
    manifest, uci = baseline(tmp_path)
    mutated = write_mutated(
        tmp_path, manifest.read_text(),
        lambda b: add_batch_line(b, "set network.lan.device='eth1'"),
        rebuild_uci=True, uci=uci,
    )
    result = run_check(mutated, uci)
    assert result.returncode == 1
    hits = lines_with(result, "hard-codes a physical or radio name")
    assert hits and any("eth1" in line for line in hits)


def test_zone_reference_wan_value_is_not_flagged(tmp_path):
    manifest, uci = baseline(tmp_path)
    mutated = write_mutated(
        tmp_path, manifest.read_text(),
        lambda b: add_batch_line(b, "set firewall.owtests.src='wan'"),
        rebuild_uci=True, uci=uci,
    )
    result = run_check(mutated, uci)
    assert not lines_with(result, "hard-codes a physical or radio name")


def test_stale_uci_file_crlf(tmp_path):
    manifest, uci = baseline(tmp_path)  # passes with byte-identical files
    target = next(uci.glob("*.uci"))
    data = target.read_bytes()
    target.write_bytes(data.replace(b"\n", b"\r\n"))
    result = run_check(manifest, uci)
    assert result.returncode == 1
    assert lines_with(result, "stale")


def test_hard_coded_radio_section_in_two_part_path(tmp_path):
    manifest, uci = baseline(tmp_path)
    mutated = write_mutated(
        tmp_path, manifest.read_text(),
        lambda b: add_batch_line(b, "set wireless.radio0=wifi-device"),
        rebuild_uci=True, uci=uci,
    )
    result = run_check(mutated, uci)
    assert result.returncode == 1
    hits = lines_with(result, "hard-codes a physical or radio name")
    assert hits and any("radio0" in line for line in hits)
    mutated2 = write_mutated(
        tmp_path, manifest.read_text(),
        lambda b: add_batch_line(b, "set wireless.default_radio=wifi-iface"),
        rebuild_uci=True, uci=uci,
    )
    result2 = run_check(mutated2, uci)
    assert not lines_with(result2, "hard-codes a physical or radio name")


def test_duplicated_manifest_entry(tmp_path):
    manifest, uci = baseline(tmp_path)
    text = manifest.read_text()
    parts = block_list(text)
    idx = next(i for i, p in enumerate(parts) if f"id = '{CTL}'" in p)
    parts.insert(idx, parts[idx])
    manifest.write_text("[[control]]".join(parts))
    rebuilt = run_build(manifest, uci)
    assert rebuilt.returncode == 0, rebuilt.stderr
    result = run_check(manifest, uci)
    assert result.returncode == 1
    assert lines_with(result, f"{CTL} standard: duplicate entry")


def test_f1_lab_bound_batch_headers():
    expected = {
        "standard": ["OW-MGMT-02", "OW-NTP-01"],
        "hardened": ["OW-MGMT-02", "OW-NTP-01", "OW-ZONE-02",
                     "OW-DNS-06", "OW-DHCP-01", "OW-LOG-01"],
        "lockdown": ["OW-MGMT-02", "OW-NTP-01", "OW-ZONE-02",
                     "OW-DNS-06", "OW-DHCP-01", "OW-LOG-01",
                     "OW-DNS-07", "OW-DNS-08"],
    }
    for tier, ids in expected.items():
        line = (PROFILES / "openwrt" / f"{tier}.uci").read_text().splitlines()[2]
        assert line == ("# lab-bound batches (lab-r1 names, not portable): "
                        + ", ".join(ids))


def test_f1_lab_batch_requires_declaration(tmp_path):
    manifest, uci = baseline(tmp_path)
    text = manifest.read_text()
    mutations = [
        ("OW-MGMT-02", "standard",
         lambda block: block.replace("lab_bound = ['batch', 'check']",
                                     "lab_bound = ['check']")),
        ("OW-MGMT-03", "standard",
         lambda block: add_batch_line(block, "set system.ntp.interface='lab'")),
    ]
    for pos, (control_id, tier, mutate) in enumerate(mutations):
        changed = write_control_mutation(
            tmp_path, text, control_id, tier, mutate, True, uci,
            name=f"f1-{pos}.toml",
        )
        result = run_check(changed, uci)
        assert result.returncode == 1
        assert lines_with(result, "lab name in batch not declared in lab_bound")


def test_f2_lab_check_requires_declaration(tmp_path):
    manifest, uci = baseline(tmp_path)
    changed = write_control_mutation(
        tmp_path, manifest.read_text(), "OW-DHCP-01", "hardened",
        lambda block: block.replace("lab_bound = ['batch', 'check']",
                                    "lab_bound = ['batch']"),
        True, uci,
    )
    result = run_check(changed, uci)
    assert result.returncode == 1
    assert lines_with(result, "lab name in check not declared in lab_bound")


def test_f2_lab_bound_part_that_is_empty_is_flagged(tmp_path):
    manifest, uci = baseline(tmp_path)
    changed = write_control_mutation(
        tmp_path, manifest.read_text(), "OW-WIFI-02", "standard",
        lambda block: block.replace("lab_bound = []",
                                    "lab_bound = ['check']"),
        False, uci,
    )
    result = run_check(changed, uci)
    assert result.returncode == 1
    assert lines_with(
        result,
        "OW-WIFI-02 standard: lab_bound lists check but it is empty",
    )


def test_f3_live_and_config_kinds_in_real_manifest():
    controls = tomllib.load(open(REAL_MANIFEST, "rb"))["control"]
    by_key = {(entry["id"], entry["tier"]): entry for entry in controls}
    for key in [("OW-MGMT-01", "standard"), ("OW-MGMT-01", "lockdown"),
                ("OW-MGMT-03", "standard"), ("OW-MGMT-05", "hardened")]:
        assert by_key[key]["check_kind"] == "live"
    for key in [("OW-MGMT-07", "hardened"),
                ("OW-MGMT-09", "hardened")]:
        assert by_key[key]["check_kind"] == "config"


def test_f3_check_kind_is_computed(tmp_path):
    manifest, uci = baseline(tmp_path)
    original = manifest.read_text()
    mutations = [
        lambda block: block.replace("check_kind = 'live'",
                                    "check_kind = 'config'"),
        lambda block: re.sub(
            r"check = .*?\nexpect = .*?\ncheck_host = 'router'\n"
            r"check_from = 'effect:1'",
            "check = 'uci -q get uhttpd.main.redirect_https'\n"
            "expect = '^1$'\ncheck_host = 'router'\ncheck_from = 'derived'",
            block, count=1, flags=re.S,
        ),
    ]
    for pos, mutate in enumerate(mutations):
        changed = write_control_mutation(
            tmp_path, original, "OW-MGMT-03", "standard", mutate,
            True, uci, name=f"f3-{pos}.toml",
        )
        result = run_check(changed, uci)
        assert result.returncode == 1
        assert lines_with(result, "check_kind is")


def test_f4_conditional_batch_is_commented_out():
    for tier in ("standard", "hardened", "lockdown"):
        lines = (PROFILES / "openwrt" / f"{tier}.uci").read_text().splitlines()
        assert not any(line.startswith("set upnpd.") for line in lines)
        assert lines[3].endswith("OW-FW-06 (miniupnpd-nftables)")
        start = lines.index("# OW-FW-06 UPnP/NAT-PMP off")
        block = lines[start:start + 5]
        assert "# conditional: needs package miniupnpd-nftables; not applied by this file" in block
        assert "# set upnpd.config.enabled='0'" in block


def test_f5_setup_preconditions_and_unclassified_steps(tmp_path):
    controls = tomllib.load(open(REAL_MANIFEST, "rb"))["control"]
    log = next(entry for entry in controls
               if entry["id"] == "OW-LOG-01" and entry["tier"] == "hardened")
    assert "syslog listener on udp 514 at log_ip" in log["preconditions"]

    manifest, uci = baseline(tmp_path)
    changed = write_control_mutation(
        tmp_path, manifest.read_text(), "OW-FW-06", "standard",
        lambda block: block.replace("  'package miniupnpd-nftables',\n", ""),
        True, uci,
    )
    result = run_check(changed, uci)
    assert result.returncode == 1
    assert lines_with(result, "precondition 'package miniupnpd-nftables' missing")

    scenarios = tmp_path / "scenarios"
    shutil.copytree(ROOT / "lab" / "scenarios" / "openwrt", scenarios)
    target = scenarios / "ow-log-02-log-size.toml"
    scenario_text = target.read_text()
    target.write_text(scenario_text.replace("setup = [", "setup = ['new_step_x', ", 1))
    result = run_check(manifest, uci, scenarios_dir=scenarios)
    assert result.returncode == 1
    assert lines_with(result, "unclassified setup step new_step_x")


def test_f6_step_up_documents_replaced_option_without_delete():
    lines = (PROFILES / "openwrt" / "lockdown.uci").read_text().splitlines()
    assert any(line.startswith("# step-up from standard: replaces ")
               and "dropbear.@dropbear[0].Interface" in line for line in lines)
    assert not any(line.startswith("delete dropbear") for line in lines)


def test_f7_openwrt_physical_name_forms(tmp_path):
    manifest, uci = baseline(tmp_path)
    original = manifest.read_text()
    for pos, value in enumerate(("wlan0-1", "phy0-ap0", "eth0:1")):
        changed = write_control_mutation(
            tmp_path, original, "OW-MGMT-03", "standard",
            lambda block, value=value: add_batch_line(
                block, f"set network.test.device='{value}'"),
            True, uci, name=f"f7-{pos}.toml",
        )
        result = run_check(changed, uci)
        assert result.returncode == 1
        assert lines_with(result, "hard-codes a physical or radio name")

    changed = write_control_mutation(
        tmp_path, original, "OW-MGMT-03", "standard",
        lambda block: add_batch_line(block, "set network.test.device='br-lan'"),
        True, uci, name="f7-br-lan.toml",
    )
    result = run_check(changed, uci)
    assert not lines_with(result, "hard-codes a physical or radio name")


def test_g1_scenario_field_mutations(tmp_path):
    manifest, uci = baseline(tmp_path)
    original = manifest.read_text()
    cases = [
        ("OW-FW-01", "standard",
         lambda block: block.replace(
             "expect = '^input_wan -> drop_from_wan$'",
             "expect = '^wrong$'"), "expect differs from"),
        ("OW-MGMT-03", "standard",
         lambda block: block.replace("redirect_https='1'", "redirect_https='0'", 1),
         "batch differs from"),
        ("OW-FW-01", "standard",
         lambda block: block.replace("check_host = 'router'", "check_host = 'lab'"),
         "check_host is"),
        ("OW-FW-02", "standard",
         lambda block: block.replace("ow-fw-02-synflood-protect.toml",
                                     "ow-fw-03-drop-invalid.toml"),
         "batch differs from"),
        ("OW-FW-01", "standard",
         lambda block: block.replace("check_from = 'effect:1'",
                                     "check_from = 'effect:9'"),
         "has no such step"),
    ]
    for pos, (control_id, tier, mutate, fragment) in enumerate(cases):
        changed = write_control_mutation(
            tmp_path, original, control_id, tier, mutate, True, uci,
            name=f"g1-{pos}.toml",
        )
        result = run_check(changed, uci)
        assert result.returncode == 1
        assert lines_with(result, fragment)


def test_g1_emptied_batch_without_a_carrier_is_flagged(tmp_path):
    manifest, uci = baseline(tmp_path)
    changed = write_control_mutation(
        tmp_path, manifest.read_text(), "OW-FW-04", "hardened",
        lambda block: re.sub(
            r"batch = \[\n.*?\n\]", "batch = []", block,
            count=1, flags=re.S,
        ),
        True, uci,
    )
    result = run_check(changed, uci)
    assert result.returncode == 1
    assert lines_with(result, "OW-FW-04 hardened: batch differs from")


def test_g5_empty_control_block_names_shared_scenario_change():
    marker = "# no lines of its own: the change is in OW-ZONE-02 (same scenario)"
    assert "# OW-FW-08" not in (PROFILES / "openwrt" / "standard.uci").read_text()
    for tier in ("hardened", "lockdown"):
        text = (PROFILES / "openwrt" / f"{tier}.uci").read_text()
        assert "# OW-FW-08" in text
        assert marker in text


def test_schema_new_manifest_fields_have_required_types():
    controls = tomllib.load(open(REAL_MANIFEST, "rb"))["control"]
    for entry in controls:
        assert isinstance(entry["check_from"], str)
        assert isinstance(entry["check_kind"], str)
        assert isinstance(entry["lab_bound"], list)
        assert all(isinstance(part, str) for part in entry["lab_bound"])


def test_schema_non_string_check_from_is_flagged_without_traceback(tmp_path):
    manifest, uci = baseline(tmp_path)
    original = manifest.read_text()
    for pos, value in enumerate(("5", "['effect:0']")):
        changed = write_control_mutation(
            tmp_path, original, "OW-FW-01", "standard",
            lambda block, value=value: block.replace(
                "check_from = 'effect:1'", f"check_from = {value}"),
            False, uci, name=f"schema-check-from-{pos}.toml",
        )
        result = run_check(changed, uci)
        assert result.returncode == 1
        assert "Traceback" not in result.stdout
        assert "Traceback" not in result.stderr
        assert lines_with(
            result,
            f"OW-FW-01 standard: check_from {value} is not "
            "effect:N, post:N or derived",
        )


def test_schema_non_string_check_from_without_scenario_is_flagged(tmp_path):
    # OW-WIFI-02 is a not-yet control: no scenario, so another branch of the checker reads check_from
    manifest, uci = baseline(tmp_path)
    original = manifest.read_text()
    for pos, value in enumerate(("5", "['effect:0']")):
        changed = write_control_mutation(
            tmp_path, original, "OW-WIFI-02", "standard",
            lambda block, value=value: block.replace(
                "check_from = ''", f"check_from = {value}"),
            False, uci, name=f"schema-check-from-no-scenario-{pos}.toml",
        )
        result = run_check(changed, uci)
        assert result.returncode == 1
        assert "Traceback" not in result.stdout
        assert "Traceback" not in result.stderr
        assert lines_with(
            result,
            f"OW-WIFI-02 standard: check_from {value} is not "
            "effect:N, post:N or derived",
        )


def test_schema_wrong_types_are_flagged_without_traceback(tmp_path):
    manifest, uci = baseline(tmp_path)
    original = manifest.read_text()
    cases = [
        ("check_kind", "'live'", "5"),
        ("check_kind", "'live'", "['live']"),
        ("lab_bound", "[]", "5"),
        ("lab_bound", "[]", "[1]"),
        ("lab_bound", "[]", "['batch', 1]"),
        ("lab_bound", "[]", "{}"),
    ]
    for pos, (key, old_value, new_value) in enumerate(cases):
        changed = write_control_mutation(
            tmp_path, original, "OW-FW-01", "standard",
            lambda block, key=key, old_value=old_value,
            new_value=new_value: block.replace(
                f"{key} = {old_value}", f"{key} = {new_value}"),
            False, uci, name=f"schema-wrong-type-{pos}.toml",
        )
        result = run_check(changed, uci)
        assert result.returncode == 1
        assert "Traceback" not in result.stdout
        assert "Traceback" not in result.stderr
        assert any(
            line.startswith("OW-FW-01 standard:")
            for line in result.stdout.splitlines()
        )


def test_n1_wrong_typed_values_are_flagged_without_traceback(tmp_path):
    manifest, uci = baseline(tmp_path)
    original = manifest.read_text()
    cases = [
        *((key, "5", f"{key} must be a string, got int")
          for key in ("id", "tier", "title", "lab", "scenario",
                      "step_up_of", "form_of", "check", "expect",
                      "check_host", "notes")),
        *((key, "5", f"{key} must be a list of strings, got int")
          for key in ("preconditions", "batch")),
        ("batch", "[1]",
         "batch must be a list of strings, item 0 is int"),
        # two bad items still give one line for the key
        ("batch", "[1, 2]",
         "batch must be a list of strings, item 0 is int"),
        ("batch", "'x'", "batch must be a list of strings, got str"),
        ("expect", "['x']", "expect must be a string, got list"),
        ("scenario", "['x']", "scenario must be a string, got list"),
        ("tier", "['x']", "tier must be a string, got list"),
        ("id", "['x']", "id must be a string, got list"),
    ]
    for pos, (key, value, fragment) in enumerate(cases):
        changed = write_control_mutation(
            tmp_path, original, "OW-FW-01", "standard",
            lambda block, key=key, value=value: set_key(block, key, value),
            False, uci, name=f"n1-wrong-type-{pos}.toml",
        )
        result = run_check(changed, uci)
        assert result.returncode == 1
        assert "Traceback" not in result.stdout
        assert "Traceback" not in result.stderr
        lines = [line for line in result.stdout.splitlines() if line]
        assert len(lines) == 1
        assert fragment in lines[0]
        if key not in ("id", "tier"):
            assert lines[0].startswith("OW-FW-01 standard: ")


def test_n1_control_that_is_not_an_array_of_tables_is_reported(tmp_path):
    cases = ("control = 5\n", "control = [1, 2]\n", "[control]\nid = 'x'\n")
    for pos, text in enumerate(cases):
        manifest = tmp_path / f"n1-control-{pos}.toml"
        manifest.write_text(text)
        result = run_check(manifest, tmp_path)
        assert result.returncode == 1
        assert "Traceback" not in result.stdout
        assert "Traceback" not in result.stderr
        assert "'control' must be an array of tables ([[control]])" in result.stdout


def test_n1_run_checks_never_raises_on_a_wrong_typed_value():
    spec = importlib.util.spec_from_file_location(
        "profiles_check", PROFILES / "check.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    manifest = module.load_manifest(REAL_MANIFEST)
    doc = module.parse_tiers_doc(tiers_doc_text())
    ctx = {
        "scenarios_dir": ROOT / "lab" / "scenarios" / "openwrt",
        "uci_dir": PROFILES / "openwrt",
        "build": module.load_build_module(PROFILES),
    }
    assert module.run_checks(manifest, doc, ctx) == []

    by_key = {(item["id"], item["tier"]): (pos, item)
              for pos, item in enumerate(manifest)}
    # OW-FW-06 opt-in: its scenario setup step needs a precondition
    targets = (("OW-FW-01", "standard"),
               ("OW-MGMT-05", "hardened"),
               ("OW-WIFI-02", "standard"),
               ("OW-FW-06", "opt-in"))
    values = (5, 1.5, True, ["x"], {"a": 1}, [1])
    typed_keys = set(module.STRING_KEYS) | set(module.STRING_LIST_KEYS)
    for target in targets:
        pos, entry = by_key[target]
        for key, current in entry.items():
            for value in values:
                if value == current:
                    continue
                changed = manifest.copy()
                changed[pos] = dict(entry, **{key: value})
                problems = module.run_checks(changed, doc, ctx)
                assert isinstance(problems, list)
                wrong_typed = (
                    key in module.STRING_KEYS and not isinstance(value, str)
                ) or (
                    key in module.STRING_LIST_KEYS
                    and (not isinstance(value, list)
                         or not all(isinstance(item, str) for item in value))
                )
                if key in typed_keys and wrong_typed:
                    assert any(f"{key} must be a" in line
                               for line in problems)


def test_n2_derived_check_needs_a_derived_note(tmp_path):
    manifest, uci = baseline(tmp_path)
    original = manifest.read_text()

    def make_derived(block, with_note=False):
        block = set_key(block, "check", "'true'")
        block = set_key(block, "check_from", "'derived'")
        if with_note:
            block = set_key(block, "notes", "'''Derived check: test.'''")
        return block

    changed = write_control_mutation(
        tmp_path, original, "OW-FW-01", "standard", make_derived,
        False, uci, name="n2-derived-no-note.toml",
    )
    result = run_check(changed, uci)
    assert result.returncode == 1
    assert lines_with(result, "check_from is derived but notes") == [
        "OW-FW-01 standard: check_from is derived but notes has no "
        "'Derived check:' remark"
    ]

    changed = write_control_mutation(
        tmp_path, original, "OW-FW-01", "standard",
        lambda block: make_derived(block, with_note=True),
        False, uci, name="n2-derived-with-note.toml",
    )
    result = run_check(changed, uci)
    assert result.returncode == 1
    assert not lines_with(result, "check_from is derived but notes")

    # OW-WIFI-02 has no scenario: the note rule applies there too
    changed = write_control_mutation(
        tmp_path, original, "OW-WIFI-02", "standard",
        lambda block: set_key(block, "check_from", "'derived'"),
        False, uci, name="n2-derived-no-scenario.toml",
    )
    result = run_check(changed, uci)
    assert result.returncode == 1
    assert lines_with(result, "check_from is derived but notes") == [
        "OW-WIFI-02 standard: check_from is derived but notes has no "
        "'Derived check:' remark"
    ]


def test_n2_derived_check_that_copies_a_scenario_step_is_flagged(tmp_path):
    manifest, uci = baseline(tmp_path)

    def make_derived(block):
        block = set_key(block, "check_from", "'derived'")
        return set_key(block, "notes", "'''Derived check: test.'''")

    cases = [
        # the check of each control is a byte copy of this effect or post step
        ("OW-FW-01", "ow-fw-01-wan-input-drop.toml", "effect:1"),
        ("OW-FW-02", "ow-fw-02-synflood-protect.toml", "post:1"),
    ]
    for pos, (control_id, scenario, step) in enumerate(cases):
        changed = write_control_mutation(
            tmp_path, manifest.read_text(), control_id, "standard",
            make_derived, False, uci, name=f"n2-derived-copy-{pos}.toml",
        )
        result = run_check(changed, uci)
        assert result.returncode == 1
        assert lines_with(result, "check_from is derived but check equals") == [
            f"{control_id} standard: check_from is derived but check equals "
            f"{scenario} {step}; use check_from {step}"
        ]


# ---- probes: the new manifest field shape and host-side rules -----------------


def _set_probes(block, probes_literal):
    """Set the control's ``probes = ...`` line.  Replaces an existing
    probes block (or inserts a new one after the batch)."""
    if re.search(r"^probes = \[", block, flags=re.MULTILINE):
        return re.sub(
            r"^probes = \[\n.*?\n\]",
            f"probes = {probes_literal}",
            block, count=1, flags=re.MULTILINE | re.DOTALL,
        )
    return re.sub(
        r"(batch = \[\n(?:.*?\n)?\])\n",
        lambda m: m.group(1) + f"\nprobes = {probes_literal}\n",
        block, count=1,
    )


def test_p3_probes_with_no_batch_is_flagged(tmp_path):
    """A control with ``probes`` and no batch can never match its own
    staged text (``touched`` requires a non-empty requirements list) —
    the seal would never fire and the probes become dead weight, so the
    checker refuses."""
    manifest, uci = baseline(tmp_path)
    target_id, target_tier = "OW-MGMT-07", "hardened"

    def strip_batch(block):
        return re.sub(
            r"batch = \[\n.*?\n\]", "batch = []", block,
            count=1, flags=re.S,
        )

    changed = write_control_mutation(
        tmp_path, manifest.read_text(), target_id, target_tier,
        strip_batch, True, uci, name="p3-no-batch.toml",
    )
    result = run_check(changed, uci)
    assert result.returncode == 1
    assert lines_with(
        result,
        f"{target_id} {target_tier}: has probes but batch is empty",
    )


def test_p3_probes_with_a_placeholder_in_batch_is_flagged(tmp_path):
    """A ``{placeholder}`` in a probe-form control's batch makes the
    control unmatchable on the host (lab-bound); the checker refuses."""
    manifest, uci = baseline(tmp_path)
    target_id, target_tier = "OW-MGMT-07", "hardened"

    def add_placeholder(block):
        return block.replace(
            "batch = [\n",
            "batch = [\n  \"set firewall.{fw_wan_zone}.input='DROP'\",\n",
            1,
        )

    changed = write_control_mutation(
        tmp_path, manifest.read_text(), target_id, target_tier,
        add_placeholder, True, uci, name="p3-placeholder.toml",
    )
    result = run_check(changed, uci)
    assert result.returncode == 1
    assert lines_with(
        result,
        f"{target_id} {target_tier}: has probes but batch contains a placeholder",
    )


def test_p3_probes_with_unknown_probe_name_is_flagged(tmp_path):
    """A probe name not in the router's PROBE_TABLE is refused (the
    router would not understand the line; ``validate_probes`` says
    ``unknown-probe`` and the checker surfaces it)."""
    manifest, uci = baseline(tmp_path)
    target_id, target_tier = "OW-MGMT-07", "hardened"

    def add_unknown_probe(block):
        return _set_probes(block, '[["not-a-real-probe", "x"]]')

    changed = write_control_mutation(
        tmp_path, manifest.read_text(), target_id, target_tier,
        add_unknown_probe, True, uci, name="p3-unknown.toml",
    )
    result = run_check(changed, uci)
    assert result.returncode == 1
    hits = lines_with(result, "probes invalid")
    assert hits and any(target_id in line and target_tier in line
                        for line in hits)
    assert any("unknown-probe" in line for line in hits)


def test_p3_probes_with_a_bad_probe_field_is_flagged(tmp_path):
    """A probe field that breaks its class grammar is refused by
    ``validate_probes`` (e.g. a non-numeric PORT).  The checker must
    surface the reason without a traceback."""
    manifest, uci = baseline(tmp_path)
    target_id, target_tier = "OW-MGMT-07", "hardened"

    def add_bad_probe(block):
        return _set_probes(block,
                              '[["listen", "tcp", "any", "9999999", "any", "present"]]')

    changed = write_control_mutation(
        tmp_path, manifest.read_text(), target_id, target_tier,
        add_bad_probe, True, uci, name="p3-bad-field.toml",
    )
    result = run_check(changed, uci)
    assert result.returncode == 1
    assert "Traceback" not in result.stdout
    assert "Traceback" not in result.stderr
    hits = lines_with(result, "probes invalid")
    assert hits and any(target_id in line for line in hits)


def test_p3_probes_with_wrong_shape_is_flagged(tmp_path):
    """``probes`` must be a list-of-list-of-str (the on-wire shape the
    router will read).  A list of plain strings, a list of dicts, or a
    bare string is refused by ``check_field_types`` before the grammar
    checker ever runs."""
    manifest, uci = baseline(tmp_path)
    target_id, target_tier = "OW-MGMT-07", "hardened"
    cases = [
        ('"fail"', "must be a list of probe field lists, got str"),
        ('["fail"]', "must be a list of probe field lists, item 0 is str"),
        ('[["fail", 1]]',
         "must be a list of probe field lists, item 0 is list"),
        ('[[1, 2]]',
         "must be a list of probe field lists, item 0 is list"),
    ]
    for pos, (literal, fragment) in enumerate(cases):
        changed = write_control_mutation(
            tmp_path, manifest.read_text(), target_id, target_tier,
            lambda b, lit=literal: _set_probes(b, lit),
            False, uci, name=f"p3-shape-{pos}.toml",
        )
        result = run_check(changed, uci)
        assert result.returncode == 1
        assert "Traceback" not in result.stdout
        assert "Traceback" not in result.stderr
        assert lines_with(result, fragment)


def test_p3_probes_pass_on_every_converted_control():
    """Static sanity check on the real manifest: every entry with a
    ``probes`` key validates (the dynamic per-control tests live in
    tests/profiles/test_profiles_probes.py)."""
    result = subprocess.run(
        [sys.executable, str(PROFILES / "check.py")],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "OK" in result.stdout


def test_default_tiers_doc_absent_skips_only_the_tier_cross_check(tmp_path):
    """A tree without docs/research still runs every other
    check; the checker says it skipped the tier cross-check."""
    tree = tmp_path / "tree"
    shutil.copytree(PROFILES, tree / "profiles",
                    ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copytree(ROOT / "lab" / "scenarios" / "openwrt",
                    tree / "lab" / "scenarios" / "openwrt")
    ok = subprocess.run([sys.executable, str(tree / "profiles" / "check.py")],
                        capture_output=True, text=True)
    assert ok.returncode == 0, ok.stdout + ok.stderr
    assert "skipping the tier cross-check" in ok.stdout
    assert "tier cross-check skipped" in ok.stdout
    # a real check still fails without the doc: break a scenario reference
    manifest = tree / "profiles" / "openwrt" / "manifest.toml"
    manifest.write_text(manifest.read_text().replace(
        "scenario = 'ow-mgmt-03-uhttpd-redirect-https.toml'",
        "scenario = 'ow-mgmt-03-no-such-file.toml'"))
    bad = subprocess.run([sys.executable, str(tree / "profiles" / "check.py")],
                         capture_output=True, text=True)
    assert bad.returncode == 1, bad.stdout


def test_explicit_tiers_doc_that_is_missing_fails(tmp_path):
    manifest, uci = baseline(tmp_path)
    result = subprocess.run(
        [sys.executable, str(PROFILES / "check.py"), "--manifest",
         str(manifest), "--uci-dir", str(uci),
         "--tiers-doc", str(tmp_path / "no-such-doc.md")],
        capture_output=True, text=True)
    assert result.returncode == 1
    assert "tiers doc: cannot read" in result.stdout
