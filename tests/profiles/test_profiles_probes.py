"""Manifest ``probes`` rules (ADR-010).

A control's ``probes`` list is sealed by ``plan()`` whenever its whole batch
is staged; a failing probe rolls the change back.  This test pins the set of
converted control entries (id + tier + batch first line) so a silent change
cannot widen or shrink it, validates each list with the router's own
``validate_probes``, and feeds every converted control's own batch text
through ``newton_mcp.touched.derive_touched_ids`` to assert the control
matches itself (a wrong probe would still leave the control matchable; this
test pairs the match with the validation above).  The batch-with-one-value-
changed check guards the same value-fidelity rule ``touched`` already
enforces for the matching requirements.

The mcp dir is added to sys.path the same way ``lab/newton-lab-test.py``
adds it (the lab runner is the other caller of ``derive_touched_ids``).
``NEWTON_MANIFEST`` is left unset so ``derive_touched_ids`` reads the real
``profiles/openwrt/manifest.toml``.
"""

from __future__ import annotations

import os
import re
import sys
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MCP_DIR = ROOT / "mcp"
if str(MCP_DIR) not in sys.path:
    sys.path.insert(0, str(MCP_DIR))

import newton_mcp.probes as probes  # noqa: E402
import newton_mcp.touched as touched  # noqa: E402

MANIFEST = ROOT / "profiles" / "openwrt" / "manifest.toml"
PLACEHOLDER_RE = re.compile(r"\{[a-zA-Z_][a-zA-Z0-9_]*\}")


CONVERTED: list[tuple[str, str, list[str], list[list[str]]]] = [
    ("OW-MGMT-01", "standard",
     ["set dropbear.@dropbear[0].Interface='lan'"],
     [["listen", "tcp", "wildcard", "22", "dropbear", "absent"],
      ["listen", "tcp", "any", "22", "dropbear", "present"]]),
    ("OW-MGMT-01", "lockdown",
     ["set dropbear.@dropbear[0].DirectInterface='lan'"],
     [["proc-args", "dropbear", "-l"]]),
    ("OW-MGMT-03", "standard",
     ["set uhttpd.main.redirect_https='1'"],
     [["proc-args", "uhttpd", "-q"]]),
    ("OW-MGMT-04", "opt-in",
     ["set dropbear.@dropbear[0].PasswordAuth='0'",
      "set dropbear.@dropbear[0].RootPasswordAuth='0'"],
     [["proc-args", "dropbear", "-s"],
      ["proc-args", "dropbear", "-g"]]),
    ("OW-MGMT-05", "hardened",
     ["set dropbear.@dropbear[0].MaxAuthTries='3'",
      "set dropbear.@dropbear[0].IdleTimeout='600'"],
     [["proc-args", "dropbear", "-I 600"],
      ["proc-args", "dropbear", "-T 3"]]),
    ("OW-MGMT-07", "hardened",
     ["set system.@system[0].ttylogin='1'"],
     [["uci-equals", "system.@system[0].ttylogin", "1"]]),
    ("OW-MGMT-09", "hardened",
     ["set luci.sauth.sessiontime='600'"],
     [["uci-equals", "luci.sauth.sessiontime", "600"]]),
    ("OW-FW-02", "standard",
     ["set firewall.@defaults[0].synflood_protect='1'"],
     [["nft-rule", "inet", "fw4", "input", "present", "jump syn_flood"],
      ["nft-rule", "inet", "fw4", "syn_flood", "present", "limit rate"],
      ["uci-equals", "firewall.@defaults[0].synflood_protect", "1"]]),
    ("OW-FW-03", "standard",
     ["set firewall.@defaults[0].drop_invalid='1'"],
     [["nft-rule", "inet", "fw4", "ruleset", "min:1", "invalid : drop"],
      ["uci-equals", "firewall.@defaults[0].drop_invalid", "1"]]),
    ("OW-FW-06", "standard",
     ["set upnpd.config.enabled='0'"],
     [["listen", "udp", "any", "1900", "miniupnpd", "absent"],
      ["listen", "udp", "any", "5351", "miniupnpd", "absent"],
      ["listen", "tcp", "any", "5000", "miniupnpd", "absent"],
      ["service-running", "miniupnpd", "any", "absent"],
      ["uci-equals", "upnpd.config.enabled", "0"]]),
    ("OW-FW-06", "opt-in",
     ["set upnpd.config.enabled='1'"],
     [["listen", "udp", "any", "1900", "miniupnpd", "present"],
      ["uci-equals", "upnpd.config.enabled", "1"]]),
    ("OW-FW-07", "hardened",
     ["set firewall.bogon_wan=rule",
      "set firewall.bogon_wan.name='Drop-Bogon-WAN'",
      "set firewall.bogon_wan.src='wan'",
      "set firewall.bogon_wan.proto='all'",
      "set firewall.bogon_wan.target='DROP'",
      "add_list firewall.bogon_wan.src_ip='10.0.0.0/8'",
      "add_list firewall.bogon_wan.src_ip='172.16.0.0/12'",
      "add_list firewall.bogon_wan.src_ip='192.168.0.0/16'",
      "add_list firewall.bogon_wan.src_ip='169.254.0.0/16'"],
     [["nft-rule", "inet", "fw4", "input_wan", "present",
       "10.0.0.0/8", "Drop-Bogon-WAN"],
      ["nft-rule", "inet", "fw4", "input_wan", "present",
       "172.16.0.0/12", "Drop-Bogon-WAN"],
      ["nft-rule", "inet", "fw4", "input_wan", "present",
       "192.168.0.0/16", "Drop-Bogon-WAN"],
      ["nft-rule", "inet", "fw4", "input_wan", "present",
       "169.254.0.0/16", "Drop-Bogon-WAN"],
      ["nft-rule", "inet", "fw4", "input_wan", "absent",
       "100.64", "Drop-Bogon-WAN"],
      ["nft-rule-order", "inet", "fw4", "input_wan",
       "Allow-DHCP-Renew", "Drop-Bogon-WAN"],
      ["nft-rule-order", "inet", "fw4", "input_wan",
       "Allow-Ping", "Drop-Bogon-WAN"]]),
    ("OW-DNS-01", "standard",
     ["set dhcp.@dnsmasq[0].rebind_protection='1'",
      "set dhcp.@dnsmasq[0].rebind_localhost='0'"],
     [["conf-has", "dnsmasq", "line", "present", "stop-dns-rebind"],
      ["conf-has", "dnsmasq", "line", "absent", "rebind-localhost-ok"]]),
    ("OW-DNS-02", "standard",
     ["set dhcp.@dnsmasq[0].localservice='1'",
      "set dhcp.@dnsmasq[0].nonwildcard='1'"],
     [["conf-has", "dnsmasq", "line", "present", "local-service"],
      ["conf-has", "dnsmasq", "line", "present", "bind-dynamic"]]),
    ("OW-DNS-03", "standard",
     ["set dhcp.@dnsmasq[0].domainneeded='1'",
      "set dhcp.@dnsmasq[0].boguspriv='1'"],
     [["conf-has", "dnsmasq", "line", "present", "domain-needed"],
      ["conf-has", "dnsmasq", "line", "present", "bogus-priv"]]),
    ("OW-DNS-04", "opt-in",
     ["set dhcp.@dnsmasq[0].dnssec='1'"],
     [["conf-has", "dnsmasq", "line", "present", "dnssec"],
      ["conf-has", "dnsmasq", "substr", "present", "trust-anchors.conf"],
      ["log-has", "min:1", "DNSSEC validation enabled"]]),
    ("OW-DNS-05", "opt-in",
     ["set https-dns-proxy.@https-dns-proxy[0].resolver_url='https://dns.quad9.net/dns-query'",
      "set https-dns-proxy.@https-dns-proxy[0].bootstrap_dns='9.9.9.9,149.112.112.112'",
      "delete https-dns-proxy.config.force_dns_src_interface",
      "add_list https-dns-proxy.config.force_dns_src_interface='lab'"],
     [["uci-equals", "https-dns-proxy.@https-dns-proxy[0].resolver_url",
       "https://dns.quad9.net/dns-query"],
      ["uci-equals", "https-dns-proxy.@https-dns-proxy[0].bootstrap_dns",
       "9.9.9.9,149.112.112.112"],
      ["proc-args", "https-dns-proxy", "-r https://dns.quad9.net/dns-query"]]),
    ("OW-DNS-06", "hardened",
     ['set firewall.dns_redirect=redirect',
      "set firewall.dns_redirect.name='Redirect-DNS'",
      "set firewall.dns_redirect.src='lab'",
      "set firewall.dns_redirect.target='DNAT'",
      "set firewall.dns_redirect.proto='tcp udp'",
      "set firewall.dns_redirect.src_dport='53'",
      "set firewall.dns_redirect.dest_port='53'",
      "set firewall.dns_redirect.family='any'"],
     [["nft-rule", "inet", "fw4", "dstnat_lab", "min:2", "redirect to :53"]]),
    ("OW-DNS-07", "lockdown",
     ['set firewall.block_dot=rule',
      "set firewall.block_dot.name='Block-DoT'",
      "set firewall.block_dot.src='lab'",
      "set firewall.block_dot.dest='wan'",
      "set firewall.block_dot.proto='tcp'",
      "set firewall.block_dot.dest_port='853'",
      "set firewall.block_dot.target='REJECT'"],
     [["nft-rule", "inet", "fw4", "forward_lab", "present",
       "tcp dport 853", "jump reject_to_wan"]]),
    ("OW-DNS-08", "lockdown",
     ['set firewall.block_dns=rule',
      "set firewall.block_dns.name='Block-DNS-WAN'",
      "set firewall.block_dns.src='lab'",
      "set firewall.block_dns.dest='wan'",
      "set firewall.block_dns.proto='tcp udp'",
      "set firewall.block_dns.dest_port='53'",
      "set firewall.block_dns.target='REJECT'"],
     [["nft-rule", "inet", "fw4", "forward_lab", "min:2",
       "dport 53 ", "jump reject_to_wan"]]),
    ("OW-DHCP-02", "standard",
     ["set dhcp.wan.ignore='1'"],
     [["conf-has", "dnsmasq", "prefix", "present", "no-dhcp-interface="],
      ["uci-equals", "dhcp.wan.ignore", "1"]]),
    ("OW-NTP-01", "standard",
     ["set system.ntp.use_dhcp='0'",
      "set system.ntp.enable_server='1'",
      "set system.ntp.interface='lab'",
      "delete system.ntp.server",
      "add_list system.ntp.server='time.cloudflare.com'",
      "add_list system.ntp.server='time.google.com'",
      "add_list system.ntp.server='pool.ntp.org'"],
     [["uci-equals", "system.ntp.use_dhcp", "0"],
      ["uci-equals", "system.ntp.enable_server", "1"],
      ["proc-args", "ntpd", "-p time.cloudflare.com"],
      ["proc-args", "ntpd", "!~openwrt.pool.ntp.org"]]),
    ("OW-V6-04", "standard",
     ["set dhcp.wan.ra='disabled'",
      "set dhcp.wan.dhcpv6='disabled'"],
     [["ra-absent", "wan"],
      ["uci-equals", "dhcp.wan.ra", "disabled"],
      ["uci-equals", "dhcp.wan.dhcpv6", "disabled"]]),
    ("OW-LOG-02", "hardened",
     ["set system.@system[0].log_size='512'"],
     [["uci-equals", "system.@system[0].log_size", "512"],
      ["proc-args", "logd", "-S 512"]]),
]


def _real_manifest_controls():
    os.environ.pop("NEWTON_MANIFEST", None)
    return tomllib.loads(MANIFEST.read_text())["control"]


def _converted_index():
    by_key = {}
    for cid, tier, batch, probes_list in CONVERTED:
        by_key[(cid, tier)] = {"batch": batch, "probes": probes_list}
    return by_key


def _real_no_probe_ids():
    return {c["id"] for c in _real_manifest_controls() if "probes" not in c}


def _converted_ids():
    return {cid for cid, _tier, _batch, _probes in CONVERTED}


# ---- the explicit no-probe pin -------------------------------------------------

NO_PROBE: set[str] = {
    "OW-DHCP-01", "OW-FW-01", "OW-FW-04", "OW-FW-05", "OW-FW-08",
    "OW-FW-09", "OW-LOG-01", "OW-LOG-03", "OW-MGMT-02", "OW-MGMT-06",
    "OW-MGMT-08", "OW-SVC-01", "OW-SVC-02", "OW-UPD-01", "OW-UPD-02",
    "OW-V6-01", "OW-V6-02", "OW-V6-03", "OW-WIFI-01", "OW-WIFI-02",
    "OW-WIFI-03", "OW-WIFI-04", "OW-ZONE-01", "OW-ZONE-02", "OW-ZONE-03",
}


def test_no_probe_set_matches_the_real_manifest_exactly():
    """Pinned NO_PROBE must equal the set of manifest control ids whose
    entry has no ``probes`` key.  A silent add/remove of a converted
    entry (the manifest grows one new probe-form entry, or drops one)
    flips this set; the failure names the difference so the cause is
    obvious in CI."""
    real = _real_no_probe_ids()
    missing = NO_PROBE - real
    extra = real - NO_PROBE
    assert not missing and not extra, (
        f"NO_PROBE: missing={sorted(missing)} extra={sorted(extra)}"
    )


def test_no_probe_and_converted_partition_manifest_ids():
    """NO_PROBE and CONVERTED must be disjoint and together cover every
    manifest control id (no overlap, no gaps)."""
    real_no_probe = _real_no_probe_ids()
    real_converted = {c["id"] for c in _real_manifest_controls()
                      if "probes" in c}
    all_ids = real_no_probe | real_converted
    manifest_ids = {c["id"] for c in _real_manifest_controls()}
    assert real_no_probe.isdisjoint(real_converted), (
        f"NO_PROBE ∩ CONVERTED not empty: "
        f"{sorted(real_no_probe & real_converted)}"
    )
    assert all_ids == manifest_ids, (
        f"NO_PROBE ∪ CONVERTED != manifest ids: "
        f"missing={sorted(manifest_ids - all_ids)} "
        f"unexpected={sorted(all_ids - manifest_ids)}"
    )
    assert NO_PROBE.isdisjoint(_converted_ids()), (
        f"pinned NO_PROBE ∩ CONVERTED not empty: "
        f"{sorted(NO_PROBE & _converted_ids())}"
    )


def _expand_id_token(token: str) -> list[str]:
    """Expand an `OW-XXX-NN..MM` range token to its member ids; a plain
    id is returned as a single-element list."""
    m = re.fullmatch(r"(\w+-\w+-)(0*\d+)\.\.(0*\d+)", token)
    if not m:
        return [token]
    prefix, start_s, end_s = m.groups()
    width = len(start_s)
    return [f"{prefix}{i:0{width}d}" for i in range(int(start_s), int(end_s) + 1)]


def _touched_paragraph():
    skill = (ROOT / "SKILL.md").read_text()
    lines = skill.splitlines()
    start = end = None
    for i, line in enumerate(lines):
        if line.startswith("**Touched controls run their live checks"):
            start = i
        elif start is not None and line.startswith("Timeouts:"):
            end = i
            break
    assert start is not None and end is not None, (
        "could not find the 'Touched controls run their live checks' "
        "paragraph in SKILL.md"
    )
    return " ".join(lines[start:end])


def test_skill_md_names_every_no_probe_and_converted_id():
    """The ADR-010 paragraph in SKILL.md must mention every NO_PROBE id
    and every CONVERTED id (plain substring or expanded `OW-XXX-NN..MM`
    range).  The pin lives in this test: a doc edit that drops an id
    fails here, and a manifest id that is not in the doc fails here."""
    paragraph = _touched_paragraph()
    expected = NO_PROBE | _converted_ids()
    ids_in_paragraph: set[str] = set()
    for token in re.split(r"[\s,()]+", paragraph):
        if not token:
            continue
        # strip trailing sentence punctuation the markdown uses (".", ")");
        # backticks are kept off the token by the split
        token = token.rstrip(".`")
        if not token:
            continue
        ids_in_paragraph.update(_expand_id_token(token))
    missing = sorted(cid for cid in expected if cid not in ids_in_paragraph)
    assert not missing, f"SKILL.md paragraph omits ids: {missing}"


# ---- the explicit converted set ------------------------------------------------


def test_the_converted_set_matches_the_real_manifest_exactly():
    """A silent add/remove of a converted entry must fail this test.  The
    pin is the (id, tier, batch[0]) triple — adding a new probe-form
    entry without listing it here is caught by the absence; removing one
    is caught by the mismatch."""
    converted = _converted_index()
    real_keys = set()
    for control in _real_manifest_controls():
        if "probes" not in control:
            continue
        batch = control.get("batch") or []
        first = batch[0] if batch else ""
        real_keys.add((control["id"], control["tier"], first))

    expected = {(cid, tier, batch[0]) for cid, tier, batch, _ in CONVERTED}
    missing = expected - real_keys
    extra = real_keys - expected
    assert not missing, f"converted entries missing from manifest: {missing}"
    assert not extra, f"manifest has unexpected probe entries: {extra}"


def test_every_converted_control_has_a_non_empty_batch():
    for cid, tier, batch, probes_list in CONVERTED:
        assert batch, f"{cid} {tier}: batch is empty"
        assert probes_list, f"{cid} {tier}: probes is empty"
        # Per-control probe-line cap. OW-FW-07 needs 7: four
        # order-independent prefix probes plus the absent 100.64 probe
        # plus the two nft-rule-order probes.  All other controls stay
        # at or under 6.
        cap = 8 if (cid, tier) == ("OW-FW-07", "hardened") else 6
        assert len(probes_list) <= cap, (
            f"{cid} {tier}: {len(probes_list)} probes exceeds the "
            f"{cap}-line cap"
        )


def test_no_placeholder_anywhere_in_converted_batches_or_probes():
    for cid, tier, batch, probes_list in CONVERTED:
        for line in batch:
            assert not PLACEHOLDER_RE.search(line), (
                f"{cid} {tier}: batch line has a placeholder: {line!r}"
            )
        for probe in probes_list:
            joined = "\t".join(probe)
            assert not PLACEHOLDER_RE.search(joined), (
                f"{cid} {tier}: probe line has a placeholder: {probe!r}"
            )


def test_every_converted_probes_list_validates_with_validate_probes():
    """The manifest must satisfy the router's own grammar (design 3.6,
    4.3).  A control whose probes fail here would be refused by
    plan() — failing here means the manifest is invalid, not the test."""
    for cid, tier, _batch, probes_list in CONVERTED:
        try:
            normalized = probes.validate_probes(probes_list)
        except Exception as exc:
            raise AssertionError(
                f"{cid} {tier}: probes refused by validate_probes: {exc}"
            )
        assert normalized == probes_list, (
            f"{cid} {tier}: validate_probes normalized the list"
        )


def test_chain_rules_use_min_not_eq():
    """Defect 5: OW-DNS-06 (``dstnat_lab``) and
    OW-DNS-08 (``forward_lab``) use ``eq:N`` to count matching rule
    lines.  If the chain gains ANY other ``redirect to :53`` / ``dport 53
    jump reject_to_wan`` rule (e.g. a second redirect added by another
    control, or a future refactor), the count exceeds N and a correct
    apply is rolled back as a false positive.  Both must use
    ``min:N`` instead, so the probe passes for any count >= N."""
    by_key = {(cid, tier): pl for cid, tier, _b, pl in CONVERTED}
    for cid, tier in (("OW-DNS-06", "hardened"),
                      ("OW-DNS-08", "lockdown")):
        probes_list = by_key[(cid, tier)]
        assert len(probes_list) == 1, (
            f"{cid} {tier}: expected one probe, got {len(probes_list)}"
        )
        probe = probes_list[0]
        assert probe[0] == "nft-rule", probe
        # the EXPECT field is the 5th positional (after nft-rule, FAM,
        # TABLE, CHAINPOS).  ``min:N`` is the tolerant form.
        assert probe[4].startswith("min:"), (
            f"{cid} {tier}: probe expect {probe[4]!r} is not min:N; "
            f"another rule in the same chain would roll back a correct "
            f"apply (defect 5)"
        )


# ---- per-control matching through derive_touched_ids ---------------------------


@pytest.fixture(autouse=True)
def _real_manifest(monkeypatch):
    monkeypatch.delenv("NEWTON_MANIFEST", raising=False)
    # Sanity check: the real manifest is what we test against.
    assert MANIFEST.is_file()


@pytest.mark.parametrize("cid, tier, batch, _probes",
                         CONVERTED,
                         ids=[f"{c} {t}" for c, t, _, _ in CONVERTED])
def test_control_batch_matches_its_own_control(cid, tier, batch, _probes):
    """``derive_touched_ids`` returns this control when its own batch is
    staged (NEWTON_MANIFEST unset, so the real manifest is read)."""
    batch_text = "\n".join(batch)
    assert touched.derive_touched_ids(batch_text) == [cid]


@pytest.mark.parametrize("cid, tier, batch, _probes",
                         CONVERTED,
                         ids=[f"{c} {t}" for c, t, _, _ in CONVERTED])
def test_changed_value_does_not_match(cid, tier, batch, _probes):
    """Defect A: a one-value change to the control's batch must NOT
    match this control (the same value-fidelity rule ``touched`` enforces
    for requirement satisfaction)."""
    changed_batch = _one_value_variant(batch)
    assert changed_batch != batch, (
        f"{cid} {tier}: could not produce a one-value variant"
    )
    batch_text = "\n".join(changed_batch)
    assert cid not in touched.derive_touched_ids(batch_text), (
        f"{cid} {tier}: changed-value batch still matched: {batch_text!r}"
    )


def _one_value_variant(batch):
    """Flip exactly one value in the control's batch (a quoted value or
    a section-type token like ``=rule``) so the requirements stop
    matching.  Tries every ``set``/``add_list`` line until one yields a
    real change; bails out (caller asserts) if nothing did.  Mutations
    that change OPTION values come first: a section-create line mutation
    (e.g. ``=rule`` -> ``=rule9``) is skipped, because the touched
    parser drops the section-level requirement when option-level
    requirements exist (ADR-010 fix: section-level
    requirements are dropped when the control has at least one
    option-level requirement)."""
    for index in range(len(batch)):
        line = batch[index]
        # section-create lines (no quoted value) are skipped: changing
        # the section type no longer breaks the match because the
        # touched parser drops section-level requirements when the
        # control has option-level requirements.
        if re.match(r"^set\s+\S+\s*=\s*[A-Za-z0-9_-]+\s*$", line):
            continue
        for mutation in (
            lambda text: re.sub(r"'(0|1)'", "'9'", text, count=1),
            lambda text: re.sub(r"'600'", "'300'", text, count=1),
            lambda text: re.sub(r"'3'", "'9'", text, count=1),
            lambda text: re.sub(r"'lan'", "'wan'", text, count=1),
            lambda text: re.sub(r"'Drop-Bogon-WAN'", "'X-Bogon-WAN'",
                                text, count=1),
            lambda text: re.sub(r"'all'", "'tcp'", text, count=1),
            lambda text: re.sub(r"'DROP'", "'ACCEPT'", text, count=1),
            lambda text: re.sub(r"'DROP'", "'REJECT'", text, count=1),
            lambda text: re.sub(r"='1'", "='9'", text, count=1),
            lambda text: re.sub(r"='0'", "='9'", text, count=1),
            lambda text: re.sub(r"'dnssec'", "'bogusdns'", text, count=1),
            lambda text: re.sub(r"'disabled'", "'server'", text, count=1),
            lambda text: re.sub(r"'512'", "'256'", text, count=1),
            lambda text: re.sub(r"'53'", "'54'", text, count=1),
            lambda text: re.sub(r"'any'", "'ipv4'", text, count=1),
            lambda text: re.sub(r"'tcp udp'", "'tcp'", text, count=1),
            lambda text: re.sub(r"'DNAT'", "'SNAT'", text, count=1),
            lambda text: re.sub(r"'Redirect-DNS'", "'X-Redirect-DNS'",
                                text, count=1),
            lambda text: re.sub(
                r"'https://dns\.quad9\.net/dns-query'",
                "'https://dns.example/dns-query'", text, count=1),
            lambda text: re.sub(r"'9\.9\.9\.9,149\.112\.112\.112'",
                                "'8.8.8.8'", text, count=1),
            lambda text: re.sub(r"'lab'", "'loc'", text, count=1),
            lambda text: re.sub(r"'wan'", "'wan9'", text, count=1),
            lambda text: re.sub(r"'tcp'", "'udp'", text, count=1),
            lambda text: re.sub(r"'853'", "'8530'", text, count=1),
            lambda text: re.sub(r"'REJECT'", "'ACCEPT'", text, count=1),
            lambda text: re.sub(r"'Block-DoT'", "'X-DoT'",
                                text, count=1),
        ):
            new_line = mutation(line)
            if new_line != line:
                return batch[:index] + [new_line] + batch[index + 1:]
    return batch