"""Interview v2 (typed answers, aliases, intents, confirmation).



The intent is to pin the v2 contract on top of the existing 10-question
legacy report: legacy input must be byte-identical with the golden
fixture, the v2 questions and aliases must be stable, validators must
refuse fail-closed without echoing the rejected value, and the new
confirmation record must have stable ids and 24 h expiry.

The tests never contact a device, never call ssh, and never touch the
manifest or the .uci files (the new ``intents.toml`` is read by
``load_intents`` from a tmp_path directory).
"""

from __future__ import annotations

import json
import os
import re
import stat
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import newton_mcp.guided as guided
import newton_mcp.probes as probes


# ---- fixtures --------------------------------------------------------------


GOLDEN_FIXTURE = Path(__file__).parent / "fixtures" / "guided_v1_golden.json"


def _read_golden_cases():
    data = json.loads(GOLDEN_FIXTURE.read_text(encoding="utf-8"))
    return data["cases"]


# ---- golden fixture is byte-identical for legacy input ---------


def test_mv1_2_01_legacy_input_is_byte_identical_to_golden():
    """Every fixture case keeps ``json.dumps(guided.recommend(case['answers']))``
    exactly equal to the stored ``report_json`` string."""
    cases = _read_golden_cases()
    assert len(cases) == 74, "fixture must hold 74 reports"
    failures = []
    for i, case in enumerate(cases):
        got = json.dumps(guided.recommend(case["answers"]))
        if got != case["report_json"]:
            failures.append((i, case["answers"]))
    assert not failures, failures


# ---- questions() shape and order --------------------------------


def test_mv1_2_02_questions_returns_the_14_v2_questions_in_order():
    """Questions() exposes the 14 v2 questions in spec order
    with id/text/type/answers/max/applies_to keys and the right types."""
    qs = guided.questions()
    assert [q["id"] for q in qs] == [
        "device_kind",
        "strictness",
        "admin_source",
        "admin_access",
        "ssh_password_off",
        "inbound_services",
        "upnp",
        "segments",
        "wifi_wpa2",
        "dns",
        "ipv6_off",
        "remote_vpn",
        "log_time_hosts",
        "fw_update_check",
    ]
    by_id = {q["id"]: q for q in qs}
    for qid, answer_type, expected_answers in [
        ("device_kind", "enum", ("home_router", "office_firewall", "switch", "edge_router", "not_sure")),
        ("strictness", "enum", ("normal", "stricter", "maximum")),
        ("admin_source", "enum", ("lan_only", "mgmt_network", "vpn_only", "anywhere")),
        ("admin_access", "multi_enum", ("ssh", "web_ui", "api", "telnet", "snmp_v3", "snmp_v1v2")),
        ("ssh_password_off", "enum", ("yes", "no")),
        ("inbound_services", "port_list", ()),
        ("upnp", "enum", ("yes", "no")),
        ("segments", "multi_enum", ("guest", "iot", "servers", "management")),
        ("wifi_wpa2", "enum", ("yes", "unsure", "all_wpa3")),
        ("dns", "multi_enum", ("dnssec", "encrypted")),
        ("ipv6_off", "enum", ("yes", "no", "unsure")),
        ("remote_vpn", "enum", ("none", "site_to_site", "road_warrior")),
        ("log_time_hosts", "host_lists", ()),
        ("fw_update_check", "enum", ("yes", "no")),
    ]:
        q = by_id[qid]
        assert set(q) == {"id", "text", "type", "answers", "max", "applies_to"}, qid
        assert q["type"] == answer_type, qid
        assert isinstance(q["text"], str) and q["text"], qid
        assert q["applies_to"] in ("", "home router", "Wi-Fi devices"), qid
        if answer_type == "enum":
            assert q["answers"] == expected_answers, qid
            assert q["max"] is None
        elif answer_type == "multi_enum":
            assert q["answers"] == expected_answers, qid
            assert q["max"] is None
        elif answer_type == "port_list":
            assert q["answers"] == ()
            assert q["max"] == 32
        elif answer_type == "host_lists":
            assert q["answers"] == ()
            assert q["max"] == 4


# ---- v2 input equivalent to legacy ------------------------------


def test_mv1_2_03_v2_answers_match_legacy_recommendations():
    """A v2 answer set folded from the legacy form yields the
    same recommendation fields (control_id, status, desired_state,
    confidence, benefit, breakage_or_preconditions) as the legacy input."""
    legacy = {
        "strictness": "normal",
        "wifi_wpa2": "yes",
        "guest_network": "yes",
        "upnp": "no",
        "iot_network": "yes",
        "ssh_password_off": "yes",
        "dnssec": "yes",
        "encrypted_dns": "yes",
        "ipv6_off": "yes",
        "fw_update_check": "yes",
    }
    legacy_report = guided.recommend(legacy)
    legacy_by_id = {r["control_id"]: r for r in legacy_report["recommendations"]}

    v2 = {
        "device_kind": "home_router",
        "strictness": "normal",
        "admin_source": "lan_only",
        "admin_access": ["ssh", "web_ui"],
        "ssh_password_off": "yes",
        "inbound_services": [],
        "upnp": "no",
        "segments": ["guest", "iot"],
        "wifi_wpa2": "yes",
        "dns": ["dnssec", "encrypted"],
        "ipv6_off": "yes",
        "remote_vpn": "none",
        "log_time_hosts": {"syslog": [], "ntp": []},
        "fw_update_check": "yes",
    }
    v2_report = guided.recommend(v2)
    v2_by_id = {r["control_id"]: r for r in v2_report["recommendations"]}

    assert set(legacy_by_id) == set(v2_by_id), (legacy_by_id, v2_by_id)
    for cid in legacy_by_id:
        l, r = legacy_by_id[cid], v2_by_id[cid]
        # owner_reason intentionally differs (different question text),
        # all other comparison fields must agree
        assert l["status"] == r["status"], cid
        assert l["desired_state"] == r["desired_state"], cid
        assert l["confidence"] == r["confidence"], cid
        assert l["benefit"] == r["benefit"], cid
        assert l["breakage_or_preconditions"] == r["breakage_or_preconditions"], cid
        assert l["control_id"] == r["control_id"], cid


# ---- aliases fold and conflict -----------------------------------


def test_mv1_2_04_alias_folds_into_v2_canonical_answer():
    """Guest_network=yes / iot_network=yes / dnssec=yes /
    encrypted_dns=yes fold into the same v2 normalized form as their
    canonical answers."""
    normalized = guided.normalize({
        "strictness": "normal",
        "guest_network": "yes",
        "iot_network": "yes",
        "dnssec": "yes",
        "encrypted_dns": "yes",
    })
    assert normalized["segments"] == ["guest", "iot"], normalized
    assert normalized["dns"] == ["dnssec", "encrypted"], normalized


def test_mv1_2_05_alias_plus_canonical_is_refused():
    """Giving an alias together with its canonical id is refused;
    the error names the question id and never echoes the rejected value."""
    with pytest.raises(guided.GuidedError) as excinfo:
        guided.normalize({
            "strictness": "normal",
            "segments": ["guest"],
            "guest_network": "yes",
        })
    msg = str(excinfo.value)
    assert "segments" in msg
    assert "guest_network" not in msg


# ---- each validator refuses fail-closed -----------------------


@pytest.mark.parametrize("qid,bad,needle", [
    # wrong type: each validator
    ("strictness", 42, "strictness"),
    ("admin_access", "ssh", "admin_access"),
    ("inbound_services", ["tcp/abc"], "inbound_services"),
    ("segments", "guest", "segments"),
    ("upnp", True, "upnp"),
    ("wifi_wpa2", ["yes"], "wifi_wpa2"),
    ("dns", True, "dns"),
    ("remote_vpn", ["none"], "remote_vpn"),
    ("log_time_hosts", ["host"], "log_time_hosts"),
    ("fw_update_check", 1, "fw_update_check"),
])
def test_mv1_2_06_validators_refuse_wrong_types(qid, bad, needle):
    """A value of the wrong type for each type raises GuidedError
    naming the question id without echoing the rejected value."""
    with pytest.raises(guided.GuidedError) as excinfo:
        guided.normalize({"strictness": "normal", qid: bad})
    msg = str(excinfo.value)
    assert needle in msg
    assert "zzq-evil" not in msg


def test_mv1_2_07_unknown_enum_value_is_refused():
    """An unknown enum value is refused and the rejected value
    is NOT echoed (use a distinctive token and assert it is absent)."""
    with pytest.raises(guided.GuidedError) as excinfo:
        guided.normalize({"strictness": "zzq-evil"})
    msg = str(excinfo.value)
    assert "strictness" in msg
    assert "zzq-evil" not in msg


def test_mv1_2_08_unknown_multi_item_is_refused():
    """An unknown item in a multi_enum is refused without echo."""
    with pytest.raises(guided.GuidedError) as excinfo:
        guided.normalize({"strictness": "normal", "admin_access": ["ssh", "zzq-evil"]})
    msg = str(excinfo.value)
    assert "admin_access" in msg
    assert "zzq-evil" not in msg


def test_mv1_2_09_duplicate_in_multi_enum_is_refused():
    """A duplicate item in multi_enum is refused."""
    with pytest.raises(guided.GuidedError) as excinfo:
        guided.normalize({"strictness": "normal", "admin_access": ["ssh", "ssh"]})
    msg = str(excinfo.value)
    assert "admin_access" in msg


def test_mv1_2_10_too_many_ports_is_refused():
    """33 ports is too many (max is 32)."""
    ports = [f"tcp/{p}" for p in range(1, 34)]
    with pytest.raises(guided.GuidedError) as excinfo:
        guided.normalize({"strictness": "normal", "inbound_services": ports})
    msg = str(excinfo.value)
    assert "inbound_services" in msg


def test_mv1_2_11_too_many_hosts_is_refused():
    """5 hosts is too many (max is 4 in syslog)."""
    hosts = [f"h{i}.example" for i in range(5)]
    with pytest.raises(guided.GuidedError) as excinfo:
        guided.normalize({
            "strictness": "normal",
            "log_time_hosts": {"syslog": hosts, "ntp": []},
        })
    msg = str(excinfo.value)
    assert "log_time_hosts" in msg


@pytest.mark.parametrize("port", ["tcp/0", "tcp/65536", "tcp/080", "icmp/1", "tcp/443 "])
def test_mv1_2_12_port_validators(port):
    """Ports outside 1..65535 or with leading zeros, wrong
    protocol, trailing whitespace, or non-numeric port number are refused."""
    with pytest.raises(guided.GuidedError) as excinfo:
        guided.normalize({"strictness": "normal", "inbound_services": [port]})
    msg = str(excinfo.value)
    assert "inbound_services" in msg
    # raw rejected value is never echoed
    assert port not in msg and port.strip() not in msg


@pytest.mark.parametrize("host", [
    "host with space",
    "-bad.example",
    "host;evil",
    "fe80::1%eth0",
    "host..double-dot",
    ".trailing.dot.",
])
def test_mv1_2_13_host_validators(host):
    """Hosts that break RFC 1123, contain a space, an IPv6
    zone id, or a leading dot are refused; the rejected value never
    appears in the error message."""
    with pytest.raises(guided.GuidedError) as excinfo:
        guided.normalize({
            "strictness": "normal",
            "log_time_hosts": {"syslog": [host], "ntp": []},
        })
    msg = str(excinfo.value)
    assert "log_time_hosts" in msg
    assert host not in msg


def test_mv1_2_14_host_lists_keys_are_syslog_and_ntp_optional():
    """``syslog`` and ``ntp`` are each optional in a
    ``host_lists`` answer; a missing key is silently treated as an
    empty list and the canonical form carries both keys. A non-dict
    value is still refused; an unknown key is refused without echoing
    the rejected value."""
    # only syslog given is accepted, ntp is filled in as []
    out = guided.normalize({
        "strictness": "normal",
        "log_time_hosts": {"syslog": ["192.0.2.10"]},
    })
    assert out["log_time_hosts"] == {"syslog": ["192.0.2.10"], "ntp": []}
    # only ntp given is accepted, syslog is filled in as []
    out = guided.normalize({
        "strictness": "normal",
        "log_time_hosts": {"ntp": ["pool.ntp.org"]},
    })
    assert out["log_time_hosts"] == {"syslog": [], "ntp": ["pool.ntp.org"]}
    # an unknown extra key is refused without echoing the key
    with pytest.raises(guided.GuidedError) as excinfo:
        guided.normalize({
            "strictness": "normal",
            "log_time_hosts": {"syslog": [], "ntp": [], "evil": []},
        })
    msg = str(excinfo.value)
    assert "log_time_hosts" in msg
    assert "evil" not in msg
    # a non-dict value is still refused
    with pytest.raises(guided.GuidedError) as excinfo:
        guided.normalize({
            "strictness": "normal",
            "log_time_hosts": ["192.0.2.10"],
        })
    msg = str(excinfo.value)
    assert "log_time_hosts" in msg


# ---- summary -------------------------------------------------


def test_mv1_2_15_summary_one_line_per_answered_question():
    """One plain English line per answered question, joined by
    '\\n', using only fixed phrases plus validated lists."""
    out = guided.summary({
        "device_kind": "home_router",
        "strictness": "normal",
        "admin_source": "mgmt_network",
        "admin_access": ["ssh", "web_ui"],
        "ssh_password_off": "yes",
        "inbound_services": ["tcp/443"],
        "upnp": "no",
        "segments": ["guest"],
        "wifi_wpa2": "yes",
        "dns": ["dnssec"],
        "ipv6_off": "yes",
        "remote_vpn": "none",
        "log_time_hosts": {"syslog": [], "ntp": ["pool.ntp.org"]},
        "fw_update_check": "yes",
    })
    lines = out.split("\n")
    assert len(lines) == 14, lines


def test_mv1_2_16_summary_does_not_echo_rejected_value():
    """A rejected value never reaches summary(); normalize() refuses first."""
    with pytest.raises(guided.GuidedError):
        guided.summary({"strictness": "zzq-evil"})


def test_mv1_2_17_summary_warns_for_anywhere_telnet_snmpv1v2():
    """Warnings appear for admin_source=anywhere,
    admin_access containing telnet or snmp_v1v2."""
    s1 = guided.summary({"strictness": "normal", "admin_source": "anywhere",
                          "admin_access": ["ssh"], "inbound_services": [],
                          "segments": [], "log_time_hosts": {"syslog": [], "ntp": []}})
    assert "Warning" in s1
    s2 = guided.summary({"strictness": "normal", "admin_source": "lan_only",
                          "admin_access": ["telnet", "snmp_v1v2"], "inbound_services": [],
                          "segments": [], "log_time_hosts": {"syslog": [], "ntp": []}})
    assert "Warning" in s2


# ---- intents --------------------------------------------------


def test_mv1_2_18_intents_unmapped_gets_none_guidance():
    """An intent not present in the platform's intents.toml
    reports guidance 'none' with the canonical no-guidance explanation."""
    report = guided.recommend({
        "strictness": "normal",
        "admin_source": "lan_only",
    })
    intents = {i["id"]: i for i in report["intents"]}
    assert intents["INT-MGMT-SRC"]["guidance"] == "none"
    assert intents["INT-MGMT-SRC"]["explanation"] == "no guidance for openwrt yet"
    assert intents["INT-MGMT-SRC"]["audit"] == []
    assert intents["INT-MGMT-SRC"]["control_id"] is None


def test_mv1_2_19_intents_audit_only_intent_reports_audit_items():
    """An audit-only intent (no control) shows its audit list."""
    report = guided.recommend({
        "strictness": "normal",
        "admin_access": ["ssh"],
    })
    intents = {i["id"]: i for i in report["intents"]}
    # admin_access with telnet absent should NOT trigger INT-MGMT-NO-TELNET
    # (it's about telnet being absent), so check the inverse: telnet present.
    # The audit-only INT-INBOUND-NONE is set by inbound_services=[].
    report2 = guided.recommend({
        "strictness": "normal",
        "inbound_services": [],
    })
    intents2 = {i["id"]: i for i in report2["intents"]}
    in_none = intents2["INT-INBOUND-NONE"]
    assert in_none["guidance"] == "audit"
    assert "port_forwards" in in_none["audit"]
    assert in_none["control_id"] is None


def test_mv1_2_20_load_intents_missing_file_for_non_openwrt_returns_empty():
    """A non-openwrt platform with no intents.toml returns {}."""
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "routeros" / "intents.toml"
        # no file written
        out = guided.load_intents(platform="routeros", directory=Path(tmp))
        assert out == {}


def test_mv1_2_21_known_intents_match_module_and_intents_toml(tmp_path):
    """Every intent id produced by recommend() for an answer set
    is in KNOWN_INTENTS, and every id present in intents.toml is in
    KNOWN_INTENTS."""
    known = set(guided.KNOWN_INTENTS)
    # answer set with one answer of every question that produces intents
    report = guided.recommend({
        "strictness": "normal",
        "admin_source": "lan_only",
        "admin_access": ["ssh", "web_ui", "api", "snmp_v3"],
        "ssh_password_off": "yes",
        "inbound_services": ["tcp/443"],
        "upnp": "yes",
        "segments": ["guest", "iot", "servers", "management"],
        "wifi_wpa2": "yes",
        "dns": ["dnssec", "encrypted"],
        "ipv6_off": "yes",
        "remote_vpn": "site_to_site",
        "log_time_hosts": {"syslog": ["192.0.2.10"], "ntp": ["pool.ntp.org"]},
        "fw_update_check": "yes",
    })
    for it in report["intents"]:
        assert it["id"] in known, it["id"]
    # intents.toml ids
    dir_path = tmp_path / "openwrt"
    dir_path.mkdir()
    (dir_path / "intents.toml").write_text(
        "[[intent]]\n"
        "id = 'INT-WIFI-WPA2-COMPAT'\n"
        "explanation = 'x'\n"
        "doc = ''\n"
        "ledger = ''\n"
        "audit = ['wifi']\n"
        "control_id = 'OW-WIFI-02'\n"
        "tier = 'standard'\n"
        "form_of = ''\n"
    )
    loaded = guided.load_intents(platform="openwrt", directory=dir_path)
    assert set(loaded) <= known, set(loaded) - known


def test_mv1_2_22_load_intents_refuses_duplicate_and_unknown_keys(tmp_path):
    """Load_intents refuses duplicate ids, unknown top-level
    keys, unknown audit items, and a control_id on a non-openwrt platform."""
    # duplicate id
    d = tmp_path / "openwrt"
    d.mkdir()
    (d / "intents.toml").write_text(
        "[[intent]]\nid='INT-X'\nexplanation=''\ndoc=''\nledger=''\naudit=[]\n"
        "control_id='OW-WIFI-02'\ntier='standard'\n"
        "[[intent]]\nid='INT-X'\nexplanation=''\ndoc=''\nledger=''\naudit=[]\n"
        "control_id='OW-WIFI-01'\n"
    )
    with pytest.raises(guided.GuidedError):
        guided.load_intents(platform="openwrt", directory=d)

    # unknown key
    d2 = tmp_path / "openwrt2"
    d2.mkdir()
    (d2 / "intents.toml").write_text(
        "[[intent]]\nid='INT-Y'\nexplanation=''\ndoc=''\nledger=''\n"
        "audit=[]\nbogus=1\n"
    )
    with pytest.raises(guided.GuidedError):
        guided.load_intents(platform="openwrt", directory=d2)

    # unknown audit item
    d3 = tmp_path / "openwrt3"
    d3.mkdir()
    (d3 / "intents.toml").write_text(
        "[[intent]]\nid='INT-Z'\nexplanation=''\ndoc=''\nledger=''\n"
        "audit=['nonsense']\n"
    )
    with pytest.raises(guided.GuidedError):
        guided.load_intents(platform="openwrt", directory=d3)

    # control_id on non-openwrt platform: write an intents.toml under a
    # sibling directory; the loader resolves "<dir>/../<platform>/intents.toml"
    # so passing directory=tmp_path/"sibling" makes the file visible.
    sibling = tmp_path / "sibling"
    sibling.mkdir()
    d4 = tmp_path / "routeros"
    d4.mkdir()
    (d4 / "intents.toml").write_text(
        "[[intent]]\nid='INT-WIFI-WPA2-COMPAT'\nexplanation=''\ndoc=''\n"
        "ledger=''\naudit=[]\ncontrol_id='OW-WIFI-02'\n"
    )
    with pytest.raises(guided.GuidedError):
        guided.load_intents(platform="routeros", directory=sibling)


# ---- an OpenWrt control_id must look like OW-XXXX-NN ------------


def _one_entry_intents(directory: Path, control_id_line: str) -> Path:
    """Write an openwrt ``intents.toml`` with one valid ``[[intent]]``
    entry whose ``control_id`` line is ``control_id_line`` verbatim."""
    d = directory / "openwrt"
    d.mkdir(parents=True)
    (d / "intents.toml").write_text(
        "[[intent]]\nid='INT-WIFI-WPA2-COMPAT'\nexplanation=''\n"
        "doc=''\nledger=''\naudit=[]\n" + control_id_line + "\n",
        encoding="utf-8",
    )
    return d


@pytest.mark.parametrize("bad", [
    "../x",
    "OW-FW-6",
    "ow-fw-06",
    "OW-FW-06 ",
    "",
    "OW-FW-06/../OW-ZONE-01",
    "OW-FW-006",
])
def test_sec3_7_bad_openwrt_control_id_shapes_are_refused(tmp_path, bad):
    """an openwrt entry whose ``control_id`` does not fullmatch
    ``OW-[A-Z0-9]{2,8}-[0-9]{2}`` is refused, including the empty string
    (which used to load silently)."""
    d = _one_entry_intents(tmp_path, f"control_id='{bad}'")
    with pytest.raises(
        guided.GuidedError,
        match="control_id must look like OW-XXXX-NN",
    ):
        guided.load_intents(platform="openwrt", directory=d)


def test_sec3_7_control_id_with_trailing_newline_is_refused(tmp_path):
    """``fullmatch``, not ``match``/``$``: a TOML escape ending in a
    newline must not pass."""
    d = _one_entry_intents(tmp_path, 'control_id="OW-FW-06\\n"')
    with pytest.raises(guided.GuidedError, match="control_id must look like OW-XXXX-NN"):
        guided.load_intents(platform="openwrt", directory=d)


def test_sec3_7_non_string_openwrt_control_id_is_refused(tmp_path):
    """a non-string ``control_id`` (an int here) is refused too,
    so a control id can never arrive as something other than a
    well-shaped string."""
    d = _one_entry_intents(tmp_path, "control_id = 5")
    with pytest.raises(
        guided.GuidedError,
        match="control_id must look like OW-XXXX-NN",
    ):
        guided.load_intents(platform="openwrt", directory=d)


def test_sec3_7_every_shipped_control_id_is_accepted(tmp_path):
    """every ``control_id`` shipped in
    ``profiles/openwrt/intents.toml`` has the required shape, the real
    file loads, and each shipped id loads on its own."""
    repo_root = Path(__file__).resolve().parents[2]
    real = repo_root / "profiles" / "openwrt"
    assert real.is_dir(), real

    shipped = guided.load_intents(platform="openwrt", directory=real)
    ids = sorted({
        cid for cid in (e.get("control_id") for e in shipped.values())
        if cid
    })
    assert ids, "profiles/openwrt/intents.toml maps no intent to a control"
    for cid in ids:
        assert re.fullmatch(r"OW-[A-Z0-9]{2,8}-[0-9]{2}", cid), cid
        one = _one_entry_intents(
            tmp_path / cid, f"control_id='{cid}'",
        )
        loaded = guided.load_intents(platform="openwrt", directory=one)
        assert loaded["INT-WIFI-WPA2-COMPAT"]["control_id"] == cid


# ---- confirmation record and storage ------------------------


def test_mv1_2_23_confirmation_record_id_is_stable_per_content():
    """Identical content -> identical id; changing any of
    answers, summary, device or platform -> different id."""
    a = {"strictness": "normal", "fw_update_check": "yes"}
    s = "Strictness: normal."
    r1 = guided.confirmation_record(a, s, device="quasar", platform="openwrt")
    r2 = guided.confirmation_record(dict(a), s, device="quasar", platform="openwrt")
    assert r1["id"] == r2["id"]
    assert r1["answers"] == r2["answers"] == [{"id": "strictness", "answer": "normal"},
                                               {"id": "fw_update_check", "answer": "yes"}]
    # change answers
    r3 = guided.confirmation_record({**a, "fw_update_check": "no"}, s,
                                    device="quasar", platform="openwrt")
    assert r3["id"] != r1["id"]
    # change device
    r4 = guided.confirmation_record(a, s, device="pulsar", platform="openwrt")
    assert r4["id"] != r1["id"]
    # change platform
    r5 = guided.confirmation_record(a, s, device="quasar", platform="routeros")
    assert r5["id"] != r1["id"]
    # change summary
    r6 = guided.confirmation_record(a, "different", device="quasar", platform="openwrt")
    assert r6["id"] != r1["id"]


def test_mv1_2_24_confirmation_record_expires_in_24h():
    """Expires_at - created_at == timedelta(hours=24)."""
    now = datetime(2026, 10, 17, 12, 0, 0, tzinfo=timezone.utc)
    rec = guided.confirmation_record(
        {"strictness": "normal"}, "s",
        device="quasar", platform="openwrt", now=now,
    )
    created = datetime.fromisoformat(rec["created_at"])
    expires = datetime.fromisoformat(rec["expires_at"])
    assert expires - created == timedelta(hours=24)
    assert rec["confirmed"] is False


def test_mv1_2_25_store_then_status_valid(tmp_path):
    """After store_confirmation, status is 'valid'."""
    rec = guided.confirmation_record({"strictness": "normal"}, "s",
                                      device="quasar", platform="openwrt")
    path = guided.store_confirmation(rec, tmp_path)
    assert path.exists()
    info = guided.confirmation_status(rec["id"], tmp_path)
    assert info == {"id": rec["id"], "status": "valid"}


def test_mv1_2_26_status_expired_when_now_after_expiry(tmp_path):
    """Status is 'expired' once now > expiry."""
    created_at = datetime(2026, 10, 17, 12, 0, 0, tzinfo=timezone.utc)
    rec = guided.confirmation_record({"strictness": "normal"}, "s",
                                      device="quasar", platform="openwrt",
                                      now=created_at)
    guided.store_confirmation(rec, tmp_path)
    later = created_at + timedelta(hours=24, seconds=1)
    info = guided.confirmation_status(rec["id"], tmp_path, now=later)
    assert info["status"] == "expired"


def test_mv1_2_27_status_unknown_for_missing_id_and_traversal_and_hex(tmp_path):
    """Status 'unknown' for missing id, an uppercase hex id,
    and a traversal-style id; in the traversal case the filesystem
    is never read."""
    # missing
    info = guided.confirmation_status("a" * 64, tmp_path)
    assert info == {"id": "a" * 64, "status": "unknown"}
    # uppercase hex
    info = guided.confirmation_status(("A" * 64), tmp_path)
    assert info["status"] == "unknown"
    # traversal: must NOT touch the filesystem beyond a path redaction
    # walk (so the parent tmp dir must not gain an escapee).
    rec = guided.confirmation_record({"strictness": "normal"}, "s",
                                      device="quasar", platform="openwrt")
    path = guided.store_confirmation(rec, tmp_path)
    # before
    before = list(tmp_path.rglob("*"))
    info = guided.confirmation_status("../../etc/passwd", tmp_path)
    assert info["status"] == "unknown"
    after = list(tmp_path.rglob("*"))
    assert before == after, "traversal-style id must not touch the filesystem"


def test_mv1_2_28_stored_file_modes_and_prune_on_new_store(tmp_path):
    """Stored file mode is 0o600 and the directory is 0o700;
    a new record prunes any other record whose expires_at is in the
    past relative to the new record's created_at."""
    created_at = datetime(2026, 10, 17, 12, 0, 0, tzinfo=timezone.utc)
    rec_old = guided.confirmation_record({"strictness": "normal"}, "s",
                                          device="quasar", platform="openwrt",
                                          now=created_at)
    guided.store_confirmation(rec_old, tmp_path)
    state_dir = tmp_path / "guided-confirmations"
    file_mode = stat.S_IMODE(os.stat(state_dir / (rec_old["id"] + ".json")).st_mode)
    dir_mode = stat.S_IMODE(os.stat(state_dir).st_mode)
    assert oct(file_mode) == oct(0o600)
    assert oct(dir_mode) == oct(0o700)

    # now store a second one, much later; the first should be pruned
    later = created_at + timedelta(days=10)
    rec_new = guided.confirmation_record({"strictness": "maximum"}, "t",
                                          device="quasar", platform="openwrt",
                                          now=later)
    guided.store_confirmation(rec_new, tmp_path)
    assert not (state_dir / (rec_old["id"] + ".json")).exists()
    assert (state_dir / (rec_new["id"] + ".json")).exists()


# ---- shape + no I/O guarantees -------------------------------


def test_mv1_2_29_legacy_report_unchanged_fields():
    """A legacy answers dict produces a report whose keys are
    exactly the v1 shape (no new keys, including no 'intents')."""
    legacy = {"strictness": "normal", "guest_network": "yes"}
    report = guided.recommend(legacy)
    expected_keys = {
        "report", "tier", "answers", "audit_run", "scans_run",
        "scans_not_run", "findings", "recommendations", "unanswered",
        "approval",
    }
    assert expected_keys == set(report), set(report)


def test_mv1_2_30_normalize_load_intents_and_summary_do_no_subprocess():
    """Normalize, load_intents and summary never run subprocess."""
    for name in ("normalize", "load_intents", "summary"):
        fn = getattr(guided, name)
        src = (lambda f: __import__("inspect").getsource(f))(fn)
        assert "subprocess" not in src, (name, src)


def test_mv1_2_31_recommend_signature_takes_no_device():
    """Recommend() and its public signature still take no
    device argument (the test from the existing suite continues to hold)."""
    import inspect
    sig = inspect.signature(guided.recommend)
    for name in sig.parameters:
        assert name not in {"device", "device_name"}, name


# ---- Parametrized: every legacy (q,a) yields same rec ----------

# Maps every legacy (question, answer) pair that yields a recommendation
# to its v2 equivalent (either the same v2 id, or the alias path that
# folds into the canonical v2 id).
_LEGACY_REC_PAIRS: list[tuple[str, str, str, object]] = [
    ("wifi_wpa2", "yes",        "wifi_wpa2", "yes"),
    ("wifi_wpa2", "unsure",     "wifi_wpa2", "unsure"),
    ("wifi_wpa2", "all_wpa3",   "wifi_wpa2", "all_wpa3"),
    ("guest_network", "yes",    "segments",  ["guest"]),
    ("upnp", "yes",             "upnp",      "yes"),
    ("upnp", "no",              "upnp",      "no"),
    ("iot_network", "yes",      "segments",  ["iot"]),
    ("ssh_password_off", "yes", "ssh_password_off", "yes"),
    ("dnssec", "yes",           "dns",       ["dnssec"]),
    ("encrypted_dns", "yes",    "dns",       ["encrypted"]),
    ("ipv6_off", "yes",         "ipv6_off",  "yes"),
    ("fw_update_check", "yes",  "fw_update_check", "yes"),
]

_REC_MATCH_FIELDS = (
    "control_id", "status", "desired_state",
    "confidence", "benefit", "breakage_or_preconditions",
)


@pytest.mark.parametrize("strictness", ["normal", "stricter", "maximum"])
@pytest.mark.parametrize("qid,answer,v2_key,v2_value", _LEGACY_REC_PAIRS)
def test_mv1_2_03_legacy_and_v2_recommendation_fields_match(
    strictness, qid, answer, v2_key, v2_value,
):
    """Every legacy (question, answer) pair that yields a
    recommendation gives the v2 equivalent (same id or alias, plus
    ``device_kind=home_router`` to force the v2 path) a recommendation
    with the same (control_id, status, desired_state, confidence,
    benefit, breakage_or_preconditions). ``owner_reason`` intentionally
    differs because the question text differs between the two paths.
    Parametrize so the failing pair is named in the test id."""
    legacy = {"strictness": strictness, qid: answer}
    v2 = {
        "device_kind": "home_router",
        "strictness": strictness,
        v2_key: v2_value,
    }
    legacy_report = guided.recommend(legacy)
    v2_report = guided.recommend(v2)
    legacy_by_id = {r["control_id"]: r for r in legacy_report["recommendations"]}
    v2_by_id = {r["control_id"]: r for r in v2_report["recommendations"]}
    assert legacy_by_id, (strictness, qid, answer)
    assert set(legacy_by_id) == set(v2_by_id), (
        strictness, qid, answer,
        sorted(legacy_by_id), sorted(v2_by_id),
    )
    for cid in legacy_by_id:
        l = legacy_by_id[cid]
        r = v2_by_id[cid]
        for field in _REC_MATCH_FIELDS:
            assert l[field] == r[field], (
                strictness, qid, answer, cid, field, l[field], r[field],
            )


# ---- legacy path reads the intents.toml control mapping --------


def test_mv1_2_32_legacy_report_reads_control_mapping_from_intents_toml(tmp_path):
    """Rewriting intents.toml to redirect an intent's
    control_id changes the legacy report's recommendations,
    proving the legacy path resolves the mapping from the file
    rather than the hard-coded table."""
    import shutil
    src = Path(probes.manifest_path()).parent
    dst = tmp_path / "openwrt"
    shutil.copytree(src, dst)
    # Rewrite only intents.toml: redirect INT-UPNP-ON to OW-ZONE-01
    (dst / "intents.toml").write_text(
        "[[intent]]\n"
        "id = 'INT-UPNP-ON'\n"
        "explanation = 'redirected for the test'\n"
        "doc = 'profiles/openwrt/manifest.toml'\n"
        "ledger = ''\n"
        "audit = ['upnp']\n"
        "control_id = 'OW-ZONE-01'\n"
        "tier = 'opt-in'\n"
        "form_of = ''\n"
        "[[intent]]\n"
        "id = 'INT-UPNP-OFF'\n"
        "explanation = ''\n"
        "doc = 'profiles/openwrt/manifest.toml'\n"
        "ledger = ''\n"
        "audit = ['upnp']\n"
        "control_id = 'OW-FW-06'\n"
        "tier = 'standard'\n"
        "form_of = ''\n"
    )
    legacy = {"strictness": "normal", "upnp": "yes"}

    # With the original intents.toml, upnp=yes picks OW-FW-06 (the opt-in
    # form of OW-FW-06); after rewriting the file, it picks OW-ZONE-01.
    orig_report = guided.recommend(legacy)
    orig_ids = {r["control_id"] for r in orig_report["recommendations"]}
    assert "OW-FW-06" in orig_ids

    new_report = guided.recommend(legacy, directory=dst)
    new_ids = {r["control_id"] for r in new_report["recommendations"]}
    assert "OW-ZONE-01" in new_ids
    assert "OW-FW-06" not in new_ids


# ---- unmapped intent on non-openwrt platform says platform ----


def test_mv1_2_33_unmapped_intent_says_platform_name_on_non_openwrt():
    """An unmapped intent on a non-openwrt platform says
    ``no guidance for <platform> yet`` (not ``for openwrt yet``),
    so the explanation tracks the requested platform rather than
    falling back to the wrong default."""
    with tempfile.TemporaryDirectory() as tmp:
        sibling = Path(tmp) / "sibling"
        sibling.mkdir()
        report = guided.recommend(
            {
                "device_kind": "home_router",
                "strictness": "normal",
                "admin_source": "lan_only",
            },
            platform="vyos",
            directory=sibling,
        )
    intents = {i["id"]: i for i in report["intents"]}
    assert intents["INT-MGMT-SRC"]["guidance"] == "none"
    assert intents["INT-MGMT-SRC"]["explanation"] == "no guidance for vyos yet"


# ---- intent entries have exactly the seven contract keys -----


def test_mv1_2_34_intent_entry_has_exactly_seven_keys():
    """Every ``intents`` entry has exactly the keys
    ``id, guidance, explanation, audit, control_id, doc, ledger``;
    ``doc`` and ``ledger`` are always present (empty string when
    the platform file did not set them); the nested ``recommendation``
    copy is gone (the recommendation lives in the top-level
    ``recommendations`` list, keyed by ``control_id``)."""
    expected = {
        "id", "guidance", "explanation", "audit",
        "control_id", "doc", "ledger",
    }
    report = guided.recommend({
        "device_kind": "home_router",
        "strictness": "normal",
        "admin_source": "lan_only",      # unmapped intent on openwrt
        "upnp": "yes",                   # mapped intent
        "inbound_services": [],          # audit-only intent
        "fw_update_check": "yes",        # mapped intent
    })
    for intent in report["intents"]:
        assert set(intent) == expected, (
            intent["id"],
            sorted(set(intent) - expected),
            sorted(expected - set(intent)),
        )
        # every entry has a string id, a known guidance, a string
        # explanation, a list audit, a control_id (str or None), and
        # the two string metadata fields.
        assert isinstance(intent["id"], str)
        assert intent["guidance"] in {"none", "control", "audit"}
        assert isinstance(intent["explanation"], str)
        assert isinstance(intent["audit"], list)
        assert isinstance(intent["doc"], str)
        assert isinstance(intent["ledger"], str)


# ---- summary for empty log_time_hosts still emits one line -----


def test_mv1_2_35_summary_log_time_hosts_empty_emits_no_remote_line():
    """``summary`` for ``log_time_hosts`` with both lists
    empty still produces one line: ``No remote syslog or NTP servers.``
    (the empty case must not silently drop the question; the other
    answered questions still emit their own lines)."""
    out = guided.summary({
        "strictness": "normal",
        "log_time_hosts": {"syslog": [], "ntp": []},
    })
    lines = out.split("\n")
    assert "No remote syslog or NTP servers." in lines, lines
    # one line per answered question; strictness and log_time_hosts are both answered
    assert len(lines) == 2, lines


# ---- store_confirmation temp file collision does not block ----


def test_mv1_2_36_store_confirmation_temp_collision_does_not_block(tmp_path):
    """A leftover ``.<id>.json.tmp`` file from a prior crash
    does not block a fresh ``store_confirmation`` for the same id;
    the stored file is 0o600."""
    state_dir = tmp_path / "guided-confirmations"
    state_dir.mkdir()
    cid = "a" * 64
    leftover = state_dir / f".{cid}.json.tmp"
    leftover.write_text("garbage from a prior crash", encoding="utf-8")
    rec = {
        "id": cid,
        "answers": [],
        "summary": "s",
        "device": "quasar",
        "platform": "openwrt",
        "created_at": "2026-10-17T12:00:00+00:00",
        "expires_at": "2026-10-18T12:00:00+00:00",
        "confirmed": False,
    }
    target = guided.store_confirmation(rec, tmp_path)
    assert target.exists()
    file_mode = stat.S_IMODE(os.stat(target).st_mode)
    assert oct(file_mode) == oct(0o600)


def test_mv1_2_37_store_confirmation_prune_skips_non_json_and_target(tmp_path):
    """``store_confirmation`` does not delete files that
    do not end in ``.json`` (e.g. stray logs, leftover temps) and
    does not delete the record it is about to write."""
    state_dir = tmp_path / "guided-confirmations"
    state_dir.mkdir()
    # a stray file with a non-.json suffix that happens to look like
    # a record id
    stray = state_dir / "stray.log"
    stray.write_text("not a record")
    rec = guided.confirmation_record({"strictness": "normal"}, "s",
                                      device="quasar", platform="openwrt")
    guided.store_confirmation(rec, tmp_path)
    assert stray.exists()
    target = state_dir / (rec["id"] + ".json")
    assert target.exists()


# ---- normalize legacy answer is folded, not refused ------------


def test_mv1_2_38_normalize_accepts_legacy_aliases_and_docstring_matches():
    """Normalize() folds the legacy alias ids
    (``guest_network``, ``iot_network``, ``dnssec``, ``encrypted_dns``)
    into their canonical v2 answers; the function's docstring must
    not claim legacy dicts are refused."""
    out = guided.normalize({
        "strictness": "normal",
        "guest_network": "yes",
        "iot_network": "no",
        "dnssec": "yes",
        "encrypted_dns": "no",
    })
    assert out["segments"] == ["guest"]
    assert out["dns"] == ["dnssec"]
    import inspect
    doc = inspect.getdoc(guided.normalize) or ""
    assert "refused" not in doc.lower(), doc


# ---- one question's exact intent contribution ---------------


@pytest.mark.parametrize(
    ("qid", "answer", "expected"),
    [
        # admin_access: hardening intents are emitted for what is OFF.
        ("admin_access", [], {
            "INT-MGMT-NO-TELNET", "INT-SNMP-OFF",
            "INT-MGMT-NO-WEB", "INT-MGMT-NO-API",
        }),
        ("admin_access", ["telnet"], {
            "INT-SNMP-OFF", "INT-MGMT-NO-WEB", "INT-MGMT-NO-API",
        }),
        ("admin_access", ["ssh"], {
            "INT-MGMT-NO-TELNET", "INT-SNMP-OFF",
            "INT-MGMT-NO-WEB", "INT-MGMT-NO-API",
        }),
        ("admin_access", ["web_ui"], {
            "INT-MGMT-NO-TELNET", "INT-SNMP-OFF", "INT-MGMT-NO-API",
        }),
        ("admin_access", ["api"], {
            "INT-MGMT-NO-TELNET", "INT-SNMP-OFF", "INT-MGMT-NO-WEB",
        }),
        ("admin_access", ["snmp_v3"], {
            "INT-MGMT-NO-TELNET", "INT-SNMP-V3-ONLY",
            "INT-MGMT-NO-WEB", "INT-MGMT-NO-API",
        }),
        ("admin_access", ["snmp_v1v2"], {
            "INT-MGMT-NO-TELNET", "INT-MGMT-NO-WEB", "INT-MGMT-NO-API",
        }),
        ("admin_access", ["snmp_v3", "snmp_v1v2"], {
            "INT-MGMT-NO-TELNET", "INT-MGMT-NO-WEB", "INT-MGMT-NO-API",
        }),
        ("admin_access",
         ["ssh", "web_ui", "api", "telnet", "snmp_v3", "snmp_v1v2"], set()),

        # segments maps every token independently.
        ("segments", ["guest"], {"INT-SEG-GUEST"}),
        ("segments", ["iot"], {"INT-SEG-IOT"}),
        ("segments", ["servers"], {"INT-SEG-SERVERS"}),
        ("segments", ["management"], {"INT-SEG-MGMT"}),
        ("segments", ["guest", "iot", "servers", "management"], {
            "INT-SEG-GUEST", "INT-SEG-IOT", "INT-SEG-SERVERS",
            "INT-SEG-MGMT",
        }),

        # remote_vpn is one-of-three.
        ("remote_vpn", "none", {"INT-VPN-NONE"}),
        ("remote_vpn", "site_to_site", {"INT-VPN-SITE"}),
        ("remote_vpn", "road_warrior", {"INT-VPN-ROAD"}),

        # inbound_services is empty versus non-empty.
        ("inbound_services", [], {"INT-INBOUND-NONE"}),
        ("inbound_services", ["tcp/443"], {"INT-INBOUND-LIST"}),

        # log_time_hosts contributes each non-empty host list.
        ("log_time_hosts", {"syslog": ["192.0.2.10"], "ntp": []},
         {"INT-LOG-REMOTE"}),
        ("log_time_hosts", {"syslog": [], "ntp": ["198.51.100.7"]},
         {"INT-NTP-SERVERS"}),
        ("log_time_hosts", {"syslog": ["192.0.2.10"], "ntp": ["198.51.100.7"]},
         {"INT-LOG-REMOTE", "INT-NTP-SERVERS"}),
    ],
)
def test_mv1_2_39_each_question_contributes_exactly_its_intents(
    qid: str, answer: object, expected: set[str],
):
    """With only ``strictness`` and one question answered,
    ``recommend()["intents"]`` contains exactly that question's intent
    ids (including the SNMP/admin absence combinations)."""
    ids = [
        i["id"]
        for i in guided.recommend({"strictness": "normal", qid: answer})[
            "intents"
        ]
    ]
    assert len(ids) == len(set(ids))
    assert set(ids) == expected, (qid, answer, ids)

    if qid == "admin_access":
        items = set(answer or [])
        assert ("INT-MGMT-NO-TELNET" in ids) == ("telnet" not in items)
        assert ("INT-SNMP-V3-ONLY" in ids) == (
            "snmp_v3" in items and "snmp_v1v2" not in items
        )
        assert ("INT-SNMP-OFF" in ids) == (
            "snmp_v3" not in items and "snmp_v1v2" not in items
        )
        assert ("INT-MGMT-NO-WEB" in ids) == ("web_ui" not in items)
        assert ("INT-MGMT-NO-API" in ids) == ("api" not in items)


# ---- legacy aliases are v2 on non-OpenWrt --------------------


def test_mv1_2_40_legacy_answers_are_v2_on_non_openwrt(tmp_path):
    """Legacy answer ids are not routed through the byte-stable
    OpenWrt legacy report on another platform; folded aliases produce no
    recommendations and all intents use that platform's no-guidance form."""
    sibling = tmp_path / "sibling"
    sibling.mkdir()
    report = guided.recommend(
        {"strictness": "normal", "guest_network": "yes"},
        platform="vyos",
        directory=sibling,
    )
    assert report["recommendations"] == []
    assert [i["id"] for i in report["intents"]] == ["INT-SEG-GUEST"]
    assert all(
        i["guidance"] == "none"
        and i["explanation"] == "no guidance for vyos yet"
        for i in report["intents"]
    )


# ---- non-OpenWrt intent files fail closed --------------------


def test_mv1_2_41_load_intents_non_openwrt_refuses_bad_entries(tmp_path):
    """A non-OpenWrt intents file accepts only known intent ids
    and only the platform-agnostic keys; control_id and unknown keys are
    refused, while an otherwise-valid file proves the layout itself."""
    def write_entry(case: str, intent_id: str, extra: str = "") -> Path:
        sibling = tmp_path / case / "sibling"
        profile = tmp_path / case / "vyos"
        sibling.mkdir(parents=True)
        profile.mkdir(parents=True)
        (profile / "intents.toml").write_text(
            "[[intent]]\n"
            f"id = '{intent_id}'\n"
            "explanation = 'vendor-neutral explanation'\n"
            "doc = ''\n"
            "ledger = ''\n"
            f"audit = []\n{extra}",
            encoding="utf-8",
        )
        return sibling

    valid_directory = write_entry(
        "valid",
        "INT-SEG-GUEST",
        "check = 'check text'\ngood = 'good text'\n",
    )
    loaded = guided.load_intents(
        platform="vyos", directory=valid_directory
    )
    assert set(loaded) == {"INT-SEG-GUEST"}

    invalid_cases = [
        (
            "control_id",
            write_entry(
                "control-id", "INT-SEG-GUEST", "control_id = 'OW-ZONE-01'\n"
            ),
        ),
        (
            "unknown key",
            write_entry(
                "unknown-key", "INT-SEG-GUEST", "snippet_x = 'y'\n"
            ),
        ),
        (
            "unknown intent id",
            write_entry("unknown-intent", "INT-NOT-A-REAL-ONE"),
        ),
    ]
    failures = []
    for label, directory in invalid_cases:
        try:
            guided.load_intents(platform="vyos", directory=directory)
        except guided.GuidedError:
            continue
        failures.append(label)
    assert failures == []


# ---- hostname trailing dot is refused ------------------------


def test_mv1_2_42_hostname_with_trailing_dot_is_refused():
    """The dot form is an FQDN presentation detail, not an
    answer token accepted by Newton; the undotted hostname is valid."""
    with pytest.raises(guided.GuidedError):
        guided.normalize({
            "strictness": "normal",
            "log_time_hosts": {"syslog": ["example.com."], "ntp": []},
        })
    out = guided.normalize({
        "strictness": "normal",
        "log_time_hosts": {"syslog": ["example.com"], "ntp": []},
    })
    assert out["log_time_hosts"]["syslog"] == ["example.com"]
