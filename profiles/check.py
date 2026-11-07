#!/usr/bin/env python3
"""Check the OpenWrt profile manifest, scenarios, and generated tier files.

The checker validates manifest key types, tier membership and counts, schema
semantics, lab-bound declarations, live/config check classification,
scenario-derived batches/checks/expects/hosts/preconditions, generated .uci
freshness, unique entries, and hard-coded physical or radio names.

The tier cross-check (entries and counts against a tiers document) runs when
a tiers document is present: the one named with --tiers-doc, which must exist,
or the default docs/research/profiles-tiers-25.12.md. Without one the checker
says so and runs every other check.

Usage: python3 profiles/check.py [--manifest PATH] [--tiers-doc PATH]
                                 [--uci-dir DIR] [--scenarios-dir DIR]
"""

import argparse
import re
import tomllib
from pathlib import Path

LAB_WORDS = {
    "proven": "proven",
    "proven, audit only": "audit",
    "proven with a caveat": "caveat",
    "not yet": "not-yet",
}

TIER_SECTIONS = {
    "Standard": "standard",
    "Hardened": "hardened",
    "Lockdown": "lockdown",
    "Opt-in extras": "opt-in",
}

LAB_WORD_RE = re.compile(r"(?<![A-Za-z0-9])lab(?![A-Za-z0-9])")
LAB_ADDR_RE = re.compile(r"10\\?\.109\\?\.0\\?\.|192\\?\.168\\?\.150\\?\.")
LAB_DEVICE_RE = re.compile(
    r"(?<![A-Za-z0-9_])(eth[0-9]+|lan[1-8]|radio[0-3]|phy[0-3]|wlan[0-3])"
    r"(?![A-Za-z0-9_])"
)
LIVE_MARKERS = re.compile(
    r"/proc/|/var/etc/|/var/run/|\bnft\b|\bnetstat\b|\bpidof\b|\bps w\b|"
    r"\bubus\b|\bifstatus\b|\blogread\b|\bapk\b|\bip (-6 )?addr\b|"
    r"\bowut\b|/etc/shadow|/dev/tcp/|\bip netns\b"
)
SETUP_PRECONDITIONS = {
    "miniupnpd_install": "package miniupnpd-nftables",
    "dnsmasq_full_install": "package dnsmasq-full",
    "https_dns_proxy_install": "package https-dns-proxy",
    "r1_clock_ok": "router clock correct (NTP synced)",
    "syslog_listen_on": "syslog listener on udp 514 at log_ip",
}
# These scenario setup steps only put the lab into a known state or start a
# lab-side probe or observer. They are not conditions of the control on a real
# router, so they are not preconditions. dns_upstream_direct is on this list on
# purpose: it makes 1.1.1.1 lab-r1's only upstream so the rebind probe tests
# lab-r1's own policy; see lab/lab.example.toml, [steps.dns_upstream_direct].
LAB_ONLY_SETUP = {
    "portfwd_on", "tcpraw_on", "dhcp_probe_on", "dhcp_state_save",
    "dns_logqueries_on", "dns_nonlocal_route_on", "dns_nonlocal_src_on",
    "dns_upstream_direct", "fw_ruleset_save", "guest_ns_on", "iot_ns_on",
    "sntp_on", "ssh_observer_start", "zone_probe_on",
}


def _cells(line):
    return [c.strip() for c in line.split("|")[1:-1]]


def parse_tiers_doc(text):
    """Return {'entries': [...], 'counts': {...}, 'not_yet': set()}.

    entries: dicts with id, tier, lab and kind (plain | step-up | form).
    """
    lines = text.splitlines()
    entries = []
    section = None
    step_up = False
    subsection = False
    for line in lines:
        if line.startswith("## "):
            name = line[3:].strip()
            section = next((t for s, t in TIER_SECTIONS.items()
                            if name.startswith(s)), None)
            step_up = False
            subsection = False
            continue
        if line.startswith("###"):
            subsection = True
            continue
        if line.startswith("**Steps up in"):
            step_up = True
            continue
        if section is None or not line.lstrip().startswith("| OW-"):
            continue
        if section == "opt-in" and subsection:
            continue
        cells = _cells(line.strip())
        ctl_id, lab_word = cells[0], cells[3]
        lab = LAB_WORDS.get(lab_word)
        if lab is None:
            raise ValueError(f"unknown Lab word {lab_word!r} for {ctl_id}")
        kind = "plain"
        if " " in ctl_id:
            ctl_id, _form = ctl_id.split(" ", 1)
            kind = "form"
        elif step_up:
            kind = "step-up"
        entries.append({"id": ctl_id, "tier": section, "lab": lab,
                        "kind": kind})

    m = re.search(r"^- \*\*No tier:\*\* (OW-[A-Z0-9-]+)$", text, re.M)
    if m:
        entries.append({"id": m.group(1), "tier": "none",
                        "lab": "not-yet", "kind": "plain"})

    counts = {}
    wt = text.find("Whole tiers")
    if wt < 0:
        raise ValueError("tier doc has no 'Whole tiers' table")
    for line in text[wt:].splitlines():
        row = re.match(r"^\| (Standard|Hardened|Lockdown) \| (\d+) \|", line)
        if row:
            counts[row.group(1).lower()] = int(row.group(2))
        elif counts and not line.lstrip().startswith("|"):
            break
    m = re.search(r"^\| Opt-in extras \| (\d+) \|", text, re.M)
    if not m:
        raise ValueError("tier doc has no 'Opt-in extras' count")
    counts["opt-in"] = int(m.group(1))

    not_yet = set()
    ny = text.find("### No scenario yet")
    if ny < 0:
        raise ValueError("tier doc has no 'No scenario yet' table")
    for line in text[ny:].splitlines()[1:]:
        if line.lstrip().startswith("| OW-"):
            not_yet.add(_cells(line.strip())[0])
        elif not_yet and not line.lstrip().startswith("|"):
            break

    return {"entries": entries, "counts": counts, "not_yet": not_yet}


def load_manifest(path):
    with open(path, "rb") as fh:
        controls = tomllib.load(fh).get("control", [])
    if not isinstance(controls, list) or not all(
            isinstance(item, dict) for item in controls):
        raise ValueError("'control' must be an array of tables ([[control]])")
    return controls


def check_entries(manifest, doc, ctx=None):
    problems = []
    by_key = {(e["id"], e["tier"]): e for e in doc["entries"]}
    m_by_key = {(e.get("id", ""), e.get("tier", "")): e for e in manifest}

    for entry in doc["entries"]:
        key = (entry["id"], entry["tier"])
        men = m_by_key.get(key)
        if men is None:
            problems.append(f"{entry['id']} {entry['tier']}: "
                            f"missing from the manifest")
            continue
        if men.get("lab") != entry["lab"]:
            problems.append(f"{entry['id']} {entry['tier']}: "
                            f"lab is {men.get('lab')}, "
                            f"the tier doc says {entry['lab']}")
        want_step_up = entry["kind"] == "step-up"
        if bool(men.get("step_up_of")) != want_step_up:
            problems.append(f"{entry['id']} {entry['tier']}: step_up_of "
                            f"is {men.get('step_up_of')!r}, expected "
                            f"{'set' if want_step_up else 'empty'}")
        want_form = entry["kind"] == "form"
        if bool(men.get("form_of")) != want_form:
            problems.append(f"{entry['id']} {entry['tier']}: form_of "
                            f"is {men.get('form_of')!r}, expected "
                            f"{'set' if want_form else 'empty'}")

    for key in m_by_key:
        if key not in by_key:
            problems.append(f"{key[0]} {key[1]}: not in the tier doc")
    return problems


def check_counts(manifest, doc, ctx=None):
    problems = []
    counted = [e for e in manifest
               if not e.get("step_up_of") and not e.get("form_of")]

    def n(tiers):
        return sum(1 for e in counted if e.get("tier") in tiers)

    want = doc["counts"]
    pairs = [
        ("standard", n(("standard",))),
        ("hardened", n(("standard", "hardened"))),
        ("lockdown", n(("standard", "hardened", "lockdown"))),
        ("opt-in", n(("opt-in",))),
    ]
    for name, got in pairs:
        if got != want[name]:
            problems.append(f"tier count {name}: manifest {got}, "
                            f"tier doc {want[name]}")

    m_not_yet = {e.get("id") for e in manifest if e.get("lab") == "not-yet"}
    d_not_yet = doc["not_yet"]
    if m_not_yet != d_not_yet:
        problems.append("not-yet list differs: "
                        f"manifest only [{', '.join(sorted(m_not_yet - d_not_yet))}], "
                        f"doc only [{', '.join(sorted(d_not_yet - m_not_yet))}]")
    return problems


def check_scenarios_and_fields(manifest, doc, ctx=None):
    problems = []
    scenarios_dir = ctx["scenarios_dir"]
    for e in manifest:
        label = f"{e.get('id', '?')} {e.get('tier', '?')}"
        scenario = e.get("scenario", "")
        if e.get("lab") != "not-yet":
            if not scenario:
                problems.append(f"{label}: scenario is empty")
            elif not (scenarios_dir / scenario).is_file():
                problems.append(f"{label}: scenario file {scenario} "
                                f"not found in {scenarios_dir}")
        if e.get("batch"):
            if not e.get("check"):
                problems.append(f"{label}: batch has no check")
            if not e.get("expect"):
                problems.append(f"{label}: batch has no expect")
            if e.get("check_host") not in ("router", "lab"):
                problems.append(f"{label}: batch check_host is "
                                f"{e.get('check_host')!r}, must be "
                                f"router or lab")
            try:
                re.compile(e.get("expect", ""))
            except re.error as exc:
                problems.append(f"{label}: expect does not compile: {exc}")
    return problems


def _label(entry):
    return f"{entry.get('id', '?')} {entry.get('tier', '?')}"


def _lab_match(part, entry):
    if part == "batch":
        text = "\n".join(entry.get("batch") or [])
        patterns = (LAB_WORD_RE, LAB_ADDR_RE)
    else:
        text = f"{entry.get('check', '')}\n{entry.get('expect', '')}"
        patterns = (LAB_WORD_RE, LAB_ADDR_RE, LAB_DEVICE_RE)
    matches = [match for pattern in patterns if (match := pattern.search(text))]
    return min(matches, key=lambda match: match.start()) if matches else None


def lab_parts(entry):
    """Return manifest parts containing a lab-r1-specific name."""
    return {part for part in ("batch", "check") if _lab_match(part, entry)}


def check_lab_bound(manifest, doc, ctx=None):
    problems = []
    for entry in manifest:
        label = _label(entry)
        declared = entry.get("lab_bound")
        valid = (isinstance(declared, list)
                 and all(part in ("batch", "check") for part in declared)
                 and len(declared) == len(set(declared)))
        if not valid:
            problems.append(f"{label}: lab_bound must be a list of batch and check")
            continue
        detected = lab_parts(entry)
        for part in ("batch", "check"):
            if part in detected and part not in declared:
                match = _lab_match(part, entry)
                problems.append(
                    f"{label}: lab name in {part} not declared in lab_bound: "
                    f"{match.group(0)}"
                )
            if part in declared:
                nonempty = (bool(entry.get("batch")) if part == "batch" else
                            bool(entry.get("check") or entry.get("expect")))
                if not nonempty:
                    problems.append(f"{label}: lab_bound lists {part} but it is empty")
    return problems


def check_check_kind(manifest, doc, ctx=None):
    problems = []
    for entry in manifest:
        check = entry.get("check", "")
        computed = "" if not check else ("live" if LIVE_MARKERS.search(check)
                                          else "config")
        declared = entry.get("check_kind")
        if declared != computed:
            problems.append(f"{_label(entry)}: check_kind is {declared}, "
                            f"expected {computed}")
    return problems


def _scenario_batch_lines(scenario):
    return [line.strip() for line in (scenario.get("batch") or "").splitlines()
            if line.strip()]


def _manifest_batch_lines(entry):
    return [line.strip().replace("{lan_device}", "eth3")
            for line in (entry.get("batch") or []) if line.strip()]


def _first_batch_difference(actual, expected):
    for pos in range(max(len(actual), len(expected))):
        got = actual[pos] if pos < len(actual) else "<missing>"
        want = expected[pos] if pos < len(expected) else "<extra scenario line absent>"
        if got != want:
            return f"line {pos + 1}: {got} (scenario: {want})"
    return "unknown difference"


def check_scenario_alignment(manifest, doc, ctx=None):
    problems = []
    scenarios_dir = ctx["scenarios_dir"]
    loaded = {}
    for entry in manifest:
        label = _label(entry)
        scenario_name = entry.get("scenario", "")
        check = entry.get("check", "")
        check_from = entry.get("check_from")
        check_host = entry.get("check_host", "")

        if check and check_host not in ("router", "lab"):
            problems.append(f"{label}: check_host is {check_host}, expected router or lab")
        elif not check and check_host != "":
            problems.append(f"{label}: check_host is {check_host}, expected empty")

        if check_from == "derived" and "Derived check:" not in entry.get("notes", ""):
            problems.append(f"{label}: check_from is derived but notes has "
                            "no 'Derived check:' remark")

        if not scenario_name:
            if check_from not in ("", "derived"):
                problems.append(f"{label}: check_from {check_from} is not "
                                "effect:N, post:N or derived")
            if check_from == "" and check:
                problems.append(f"{label}: check_from is empty but check is not")
            continue

        scenario_path = scenarios_dir / scenario_name
        if not scenario_path.is_file():
            continue
        try:
            scenario = loaded.setdefault(
                scenario_name, tomllib.loads(scenario_path.read_text(encoding="utf-8"))
            )
        except (OSError, tomllib.TOMLDecodeError):
            continue

        actual_batch = _manifest_batch_lines(entry)
        expected_batch = _scenario_batch_lines(scenario)
        batch_ok = actual_batch == expected_batch
        if not actual_batch and expected_batch:
            batch_ok = any(
                other is not entry
                and other.get("scenario") == scenario_name
                and _manifest_batch_lines(other) == expected_batch
                for other in manifest
            )
        if not batch_ok:
            problems.append(f"{label}: batch differs from {scenario_name}: "
                            f"{_first_batch_difference(actual_batch, expected_batch)}")

        for setup_step in scenario.get("setup") or []:
            if setup_step in SETUP_PRECONDITIONS:
                needed = SETUP_PRECONDITIONS[setup_step]
                if needed not in (entry.get("preconditions") or []):
                    problems.append(
                        f"{label}: precondition '{needed}' missing, scenario "
                        f"{scenario_name} has setup step {setup_step}"
                    )
            elif setup_step not in LAB_ONLY_SETUP:
                problems.append(f"{label}: scenario {scenario_name} has an "
                                f"unclassified setup step {setup_step}")

        if check_from == "":
            if check:
                problems.append(f"{label}: check_from is empty but check is not")
            continue
        if check_from == "derived":
            for kind in ("effect", "post"):
                for index, step in enumerate(scenario.get(kind) or []):
                    if (check.strip()
                            and check.strip() == step.get("cmd", "").strip()):
                        problems.append(
                            f"{label}: check_from is derived but check equals "
                            f"{scenario_name} {kind}:{index}; use check_from "
                            f"{kind}:{index}"
                        )
            continue
        ref = re.fullmatch(r"(effect|post):(\d+)", str(check_from))
        if not ref:
            problems.append(f"{label}: check_from {check_from} is not "
                            "effect:N, post:N or derived")
            continue
        kind, index_text = ref.groups()
        index = int(index_text)
        steps = scenario.get(kind) or []
        if index >= len(steps):
            problems.append(f"{label}: check_from {check_from} has no such step "
                            f"in {scenario_name}")
            continue
        step = steps[index]
        if check.strip() != step.get("cmd", "").strip():
            problems.append(f"{label}: check differs from {scenario_name} "
                            f"{check_from}")
        step_expect = step.get("expect_stdout")
        if step_expect is not None:
            if entry.get("expect") != step_expect:
                problems.append(f"{label}: expect differs from {scenario_name} "
                                f"{check_from}")
        elif not entry.get("expect"):
            problems.append(f"{label}: expect differs from {scenario_name} "
                            f"{check_from}")
        expected_host = "router" if step.get("device") == "lab-r1" else "lab"
        if check_host != expected_host:
            problems.append(f"{label}: check_host is {check_host}, the scenario "
                            f"step runs on {step.get('device')}, expected "
                            f"{expected_host}")
    return problems


def load_build_module(check_dir):
    import importlib.util
    path = Path(check_dir) / "build.py"
    spec = importlib.util.spec_from_file_location("profiles_build", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def check_uci_files(manifest, doc, ctx=None):
    build = ctx["build"]
    uci_dir = ctx["uci_dir"]
    problems = []
    for tier in build.TIER_ORDER:
        try:
            fresh = build.render_uci(tier,
                                     build.select_controls(manifest, tier),
                                     manifest)
        except Exception as exc:
            problems.append(f"manifest: cannot be rendered for the .uci "
                            f"comparison ({tier}): {exc}")
            continue
        path = uci_dir / f"{tier}.uci"
        if not path.is_file():
            problems.append(f"{tier}.uci: missing")
            continue
        try:
            current = path.read_bytes()
        except OSError as exc:
            problems.append(f"{tier}.uci: cannot read {path}: "
                            f"{exc.strerror or exc}")
            continue
        if current != fresh.encode("utf-8"):
            problems.append(f"{tier}.uci: stale, differs from a fresh build "
                            f"(run profiles/build.py)")
    return problems


BATCH_LINE_RE = re.compile(r"^(set|add_list|del_list|delete)\s+"
                           r"([^=]+?)(?:=(.*))?$")
PHYS_NAME_RE = re.compile(
    r"(eth[0-9]+|lan[1-8]|radio[0-3]|phy[0-3]|wlan[0-3])"
    r"(?:[.:][0-9]+|-[0-9]+|-(?:ap|sta|mesh|mon)[0-9]+)*"
)
WAN_IF_OPTIONS = {"device", "ifname", "ports", "port", "l3_device"}
RADIO_SECTION_RE = re.compile(
    r"^(?:radio|phy)[0-3](?:[.:][0-9]+|-[0-9]+|"
    r"-(?:ap|sta|mesh|mon)[0-9]+)*$"
)


def _batch_values(value_part):
    if not value_part:
        return []
    quoted = re.findall(r"'([^']*)'|\"([^\"]*)\"", value_part)
    if quoted:
        return [a or b for a, b in quoted]
    return [value_part.strip()]


def batch_hard_codes(line):
    """Return True when a uci batch line hard-codes a physical/radio name."""
    m = BATCH_LINE_RE.match(line.strip())
    if not m:
        return False
    _op, path, value_part = m.groups()
    parts = path.strip().split(".")
    config = parts[0]
    section = parts[1] if len(parts) > 1 else ""
    option = parts[-1]

    if config == "wireless" and RADIO_SECTION_RE.match(section):
        return True
    for value in _batch_values(value_part):
        if value == "wan" and option in WAN_IF_OPTIONS:
            return True
        for word in value.split():
            if PHYS_NAME_RE.fullmatch(word):
                return True
    return False


def check_hard_coded_names(manifest, doc, ctx=None):
    problems = []
    for e in manifest:
        for line in e.get("batch") or []:
            if batch_hard_codes(line):
                problems.append(f"{e.get('id', '?')} {e.get('tier', '?')}: "
                                f"batch hard-codes a physical or radio "
                                f"name: {line}")
    return problems


def check_unique(manifest, doc, ctx=None):
    problems = []
    seen = set()
    for e in manifest:
        key = (e.get("id", ""), e.get("tier", ""))
        if key in seen:
            problems.append(f"{key[0]} {key[1]}: duplicate entry")
        seen.add(key)
    return problems


_PROBES_PLACEHOLDER_RE = re.compile(r"\{[a-zA-Z_][a-zA-Z0-9_]*\}")


def _load_probes_module():
    import sys

    repo_root = Path(__file__).resolve().parents[1]
    mcp_dir = repo_root / "mcp"
    if str(mcp_dir) not in sys.path:
        sys.path.insert(0, str(mcp_dir))
    import newton_mcp.probes  # noqa: E402
    return newton_mcp.probes


def check_probes(manifest, doc, ctx=None):
    """Every control with a ``probes`` key must validate and have a usable batch.

    ``validate_probes`` enforces the router's grammar (design 4.3 / 3.6);
    we add the host-side rules: a non-empty batch with no ``{placeholder}``
    (so the control is actually matchable by ``touched.derive_touched_ids``)
    and the shape list-of-list-of-str (the manifest cannot lie about the
    on-wire form the router will see).  A failure names the control id
    and the validator's reason so the operator sees the cause.
    """
    problems: list[str] = []
    if not any(isinstance(e, dict) and "probes" in e for e in manifest):
        return problems
    try:
        probes = _load_probes_module()
    except Exception as exc:
        return [f"manifest: cannot load newton_mcp.probes: {exc}"]
    from newton_mcp.server import NewtonError
    for e in manifest:
        if "probes" not in e:
            continue
        label = _label(e)
        probes_value = e["probes"]
        if not isinstance(probes_value, list) or not all(
            isinstance(probe, list)
            and all(isinstance(field, str) for field in probe)
            for probe in probes_value
        ):
            problems.append(f"{label}: probes must be a list of probe field "
                            "lists")
            continue
        batch = e.get("batch")
        if not isinstance(batch, list) or not batch:
            problems.append(f"{label}: has probes but batch is empty")
            continue
        for line in batch:
            if not isinstance(line, str):
                continue
            if _PROBES_PLACEHOLDER_RE.search(line):
                problems.append(
                    f"{label}: has probes but batch contains a placeholder "
                    f"(never converted on the host): {line}"
                )
                break
        try:
            probes.validate_probes(probes_value)
        except NewtonError as exc:
            problems.append(f"{label}: probes invalid: {exc}")
    return problems


STRING_KEYS = ("id", "tier", "title", "lab", "scenario", "step_up_of",
               "form_of", "check", "expect", "check_host", "notes")
STRING_LIST_KEYS = ("preconditions", "batch")
LIST_OF_STRING_LIST_KEYS = ("probes",)


def check_field_types(manifest, doc, ctx=None):
    """One line per wrong-typed key. check_from, check_kind and lab_bound are
    left out on purpose: check_scenario_alignment, check_check_kind and
    check_lab_bound already report them in their own words.  ``probes`` is
    a list-of-list-of-str (the on-wire shape); check_probes reports the
    grammar-level errors in its own words."""
    problems = []
    for entry in manifest:
        label = _label(entry)
        for key in STRING_KEYS:
            if key in entry and not isinstance(entry[key], str):
                problems.append(f"{label}: {key} must be a string, got "
                                f"{type(entry[key]).__name__}")
        for key in STRING_LIST_KEYS:
            if key not in entry:
                continue
            value = entry[key]
            if not isinstance(value, list):
                problems.append(f"{label}: {key} must be a list of strings, "
                                f"got {type(value).__name__}")
                continue
            for pos, item in enumerate(value):
                if not isinstance(item, str):
                    problems.append(f"{label}: {key} must be a list of "
                                    f"strings, item {pos} is "
                                    f"{type(item).__name__}")
                    break
        for key in LIST_OF_STRING_LIST_KEYS:
            if key not in entry:
                continue
            value = entry[key]
            if not isinstance(value, list):
                problems.append(f"{label}: {key} must be a list of probe "
                                f"field lists, got {type(value).__name__}")
                continue
            for pos, item in enumerate(value):
                if not isinstance(item, list) or not all(
                        isinstance(field, str) for field in item):
                    problems.append(f"{label}: {key} must be a list of "
                                    f"probe field lists, item {pos} is "
                                    f"{type(item).__name__}")
                    break
    return problems


CHECKS = (
    check_entries,
    check_counts,
    check_scenarios_and_fields,
    check_lab_bound,
    check_check_kind,
    check_scenario_alignment,
    check_uci_files,
    check_hard_coded_names,
    check_unique,
    check_probes,
)


# The checks that compare the manifest with the tiers document.
DOC_CHECKS = (check_entries, check_counts)


def run_checks(manifest, doc, ctx):
    # Later checks assume ordinary manifest fields have their documented types.
    if problems := check_field_types(manifest, doc, ctx):
        return problems
    problems = []
    for check in CHECKS:
        if doc is None and check in DOC_CHECKS:
            continue
        problems.extend(check(manifest, doc, ctx))
    return problems


def main(argv=None):
    here = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest",
                        default=here / "openwrt" / "manifest.toml",
                        type=Path)
    default_doc = (here.parent / "docs" / "research"
                   / "profiles-tiers-25.12.md")
    parser.add_argument("--tiers-doc", default=None, type=Path,
                        help=f"tiers document (default {default_doc}; "
                             "the tier cross-check is skipped when the "
                             "default is absent)")
    parser.add_argument("--uci-dir", default=None, type=Path,
                        help="directory of the generated .uci files "
                             "(default: the directory of --manifest)")
    parser.add_argument("--scenarios-dir",
                        default=here.parent / "lab" / "scenarios" / "openwrt",
                        type=Path,
                        help="directory of the scenario files")
    args = parser.parse_args(argv)

    try:
        manifest = load_manifest(args.manifest)
    except OSError as exc:
        print(f"manifest: cannot read {args.manifest}: "
              f"{exc.strerror or exc}")
        return 1
    except (tomllib.TOMLDecodeError, ValueError) as exc:
        print(f"manifest: cannot read {args.manifest}: {exc}")
        return 1
    doc = None
    doc_path = args.tiers_doc or default_doc
    if args.tiers_doc is None and not default_doc.is_file():
        print(f"tiers doc: {default_doc} is not in this tree; "
              f"skipping the tier cross-check")
    else:
        try:
            doc = parse_tiers_doc(doc_path.read_text())
        except OSError as exc:
            print(f"tiers doc: cannot read {doc_path}: "
                  f"{exc.strerror or exc}")
            return 1
        except ValueError as exc:
            print(f"tiers doc: cannot read {doc_path}: {exc}")
            return 1
    try:
        build = load_build_module(here)
    except Exception as exc:
        print(f"build.py: cannot load {here / 'build.py'}: {exc}")
        return 1
    if args.uci_dir is None:
        args.uci_dir = args.manifest.resolve().parent
    ctx = {"scenarios_dir": args.scenarios_dir,
           "uci_dir": args.uci_dir, "build": build}
    problems = run_checks(manifest, doc, ctx)
    if problems:
        for line in problems:
            print(line)
        return 1
    if doc is None:
        print(f"profiles/check.py: OK ({len(manifest)} manifest entries; "
              f"tier cross-check skipped)")
        return 0
    print(f"profiles/check.py: OK ({len(manifest)} manifest entries; "
          f"tiers {doc['counts']['standard']}/{doc['counts']['hardened']}"
          f"/{doc['counts']['lockdown']}; opt-in {doc['counts']['opt-in']}; "
          f"not-yet {len(doc['not_yet'])})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
