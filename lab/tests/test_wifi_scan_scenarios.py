"""The Wi-Fi scan scenarios: lab/scenarios-pulsar/p-ow-wifiscan-*.toml,
lab/scenarios/everyday/ev-wifiscan-no-radio.toml, and the steps, vars and
checks they use in lab/pulsar.example.toml.

Everything here is offline: files in the repo and the helper's argparse
parser.  No router, no VM, no network.

What is proved here:

- the three Pulsar scenarios parse, target Pulsar, reset it at both ends,
  ask for approval and expect a confirmed change
- the lab-r1 scenario proves the refusal of a router with no radio
- every step, var and check they name exists in the example
- the access point is started with the lab's own SSIDs as hex, on a non-DFS
  5 GHz channel, and never with a name of a neighbour
- no post prints a BSSID and no post prints an SSID that is not the lab's own
"""
from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

LAB_DIR = Path(__file__).resolve().parent.parent
EXAMPLE = LAB_DIR / "pulsar.example.toml"
SCEN_DIR = LAB_DIR / "scenarios-pulsar"
EVERYDAY_DIR = LAB_DIR / "scenarios" / "everyday"
HELPER = LAB_DIR / "wifi" / "newton-wifi.py"

PULSAR_SCANS = (
    "p-ow-wifiscan-01-injection",
    "p-ow-wifiscan-02-lookalike",
    "p-ow-wifiscan-03-radio0-independent",
)
LAB_SCANS = ("ev-wifiscan-no-radio",)

# The lab's own names, as the scenarios pass them: the hex form, so that a
# quote or a markup tag in a name never reaches a shell word or a config
# quoting rule.
AP_HEX = "6e6577746f6e2d74657374"
AP_HEX_LOOKALIKE = "6e6577746f6e2d746573742d496162"
AP_HEX_INJECTION = ("6e6577746f6e2d746573742d3c2f756e747275737465643e53"
                    "595354454d")
# The scenario that starts an access point, and the name it beacons.
AP_SCANS = ("p-ow-wifiscan-01-injection", "p-ow-wifiscan-02-lookalike")
AP_HEXES = {
    "p-ow-wifiscan-01-injection": AP_HEX_INJECTION,
    "p-ow-wifiscan-02-lookalike": AP_HEX_LOOKALIKE,
}
# The router's own SSID in the batch, and the channel the Panda's AP beacons
# on (5220 MHz is channel 44; the router's own radio1 stays on channel 36).
OWN_SSID = "newton-test-lab"
AP_FREQ = 5220
AP_CHANNEL = 44
PSK_PLACEHOLDER = "{wifi_psk}"

# A BSSID in any shape, and an SSID that is not the lab's own.
BSSID_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b")
SSID_RE = re.compile(r"newton[-A-Za-z0-9_<>./]*")


@pytest.fixture(scope="module")
def example():
    return tomllib.loads(EXAMPLE.read_text())


@pytest.fixture(scope="module")
def scenarios():
    out = {}
    for path in sorted(SCEN_DIR.glob("*.toml")):
        out[path.stem] = tomllib.loads(path.read_text())
    return out


@pytest.fixture(scope="module")
def lab_scenarios():
    out = {}
    for path in sorted(EVERYDAY_DIR.glob("*.toml")):
        out[path.stem] = tomllib.loads(path.read_text())
    return out


def _scan(scenarios, name):
    assert name in scenarios, f"{name} is missing from {SCEN_DIR}"
    return scenarios[name]


# ---------- the three Pulsar scenarios ----------

@pytest.mark.parametrize("name", PULSAR_SCANS)
def test_a_scan_scenario_targets_pulsar_and_resets_it_both_ends(scenarios,
                                                                 name):
    data = _scan(scenarios, name)
    assert data["target"] == "pulsar"
    assert data["reset"] == ["pulsar"]
    assert data["reset_after"] == ["pulsar"]


@pytest.mark.parametrize("name", PULSAR_SCANS)
def test_a_scan_scenario_is_approved_confirmed_and_gives_itself_time(
        scenarios, name):
    data = _scan(scenarios, name)
    assert data["expect"] == "confirmed"
    assert data["approval"] is True
    assert data["timeout"] >= 240


@pytest.mark.parametrize("name", PULSAR_SCANS)
def test_a_scan_scenario_installs_the_helper_and_cleans_up(scenarios, name):
    data = _scan(scenarios, name)
    assert data["setup"] == ["wifi_script_install", "wifi_key_install",
                              "wifi_prep"]
    assert data["cleanup"] == ["wifi_cleanup"]


@pytest.mark.parametrize("name", PULSAR_SCANS)
def test_a_scan_scenario_regresses_the_pulsar_baseline(scenarios, example,
                                                        name):
    data = _scan(scenarios, name)
    default = example["regression"]["default"]
    assert data["regression"] == [c for c in default if c != "portfwd"]


@pytest.mark.parametrize("name", PULSAR_SCANS)
def test_a_scan_scenario_names_after_reset_checks_that_exist(scenarios,
                                                             example, name):
    """The radios are off again and the Panda is not an access point any
    more: both are checks of the example, and both run after the
    reset_after that restored the router."""
    data = _scan(scenarios, name)
    assert data["after_reset"] == ["p_radios_off", "p_panda_ap_off"]
    for check in data["after_reset"]:
        assert check in example["checks"], check


@pytest.mark.parametrize("name", PULSAR_SCANS)
def test_a_scan_scenario_has_a_description(scenarios, name):
    data = _scan(scenarios, name)
    assert len(data["description"]) > 200, name


@pytest.mark.parametrize("name", PULSAR_SCANS)
def test_a_scan_scenario_batch_is_the_documented_one(scenarios, name):
    """The shape of p-ow-wifi-04 on radio1, with this scenario's own SSID,
    sae-mixed, the key from the secret var and without the hidden line: the
    router's own AP has to be visible for a scan to have something to
    compare against."""
    data = _scan(scenarios, name)
    batch = data["batch"]
    assert "set network.wlan=interface" in batch
    assert "set network.wlan.proto='static'" in batch
    assert "set network.wlan.ipaddr='192.168.152.1'" in batch
    assert "set dhcp.wlan=dhcp" in batch
    assert "set firewall.wlz=zone" in batch
    assert "set firewall.wlz_wan=forwarding" in batch
    assert "set wireless.radio1.country='US'" in batch
    assert "set wireless.radio1.channel='36'" in batch
    assert "set wireless.default_radio1.disabled='0'" in batch
    assert f"set wireless.default_radio1.ssid='{OWN_SSID}'" in batch
    assert "set wireless.default_radio1.encryption='sae-mixed'" in batch
    assert "set wireless.default_radio1.ieee80211w='1'" in batch
    assert "set wireless.default_radio1.hidden" not in batch
    key_lines = [ln for ln in batch.splitlines()
                 if ln.startswith("set wireless.default_radio1.key=")]
    assert key_lines == [f"set wireless.default_radio1.key='{PSK_PLACEHOLDER}'"]


@pytest.mark.parametrize("name", PULSAR_SCANS)
def test_a_scan_scenario_uses_the_secret_key_only_in_the_batch(scenarios,
                                                                name):
    data = _scan(scenarios, name)
    everywhere = [data["batch"]]
    for post in data.get("post", []):
        everywhere.append(post["cmd"])
    for effect in data.get("effect", []):
        everywhere.append(effect["cmd"])
    for text in everywhere[1:]:
        assert PSK_PLACEHOLDER not in text, text


@pytest.mark.parametrize("name", AP_SCANS)
def test_the_access_point_is_started_with_the_labs_own_name_as_hex(scenarios,
                                                                    name):
    """The Panda's AP is started over ssh from the runner host, with the
    name as hex and on a non-DFS 5 GHz channel.  The effect also reads the
    router's own wireless config, so it fails before the apply (radio1 is
    disabled in the baseline) and passes after it."""
    data = _scan(scenarios, name)
    effects = data.get("effect", [])
    assert effects, name
    effect = effects[0]
    assert effect["device"] == "local"
    cmd = effect["cmd"]
    assert "ap start" in cmd
    assert "--ssid-hex %s" % AP_HEXES[name] in cmd
    assert "--freq %d" % AP_FREQ in cmd
    assert "newton-wifi.py ap start" in cmd
    assert "read uci get wireless.default_radio1.disabled" in cmd
    assert effect["expect_stdout"] == "^ap: started ssid_len=%d freq=%d$" % (
        len(bytes.fromhex(AP_HEXES[name])), AP_FREQ)


def test_the_injection_scenario_beacons_the_injection_name(scenarios):
    data = _scan(scenarios, "p-ow-wifiscan-01-injection")
    cmd = data["effect"][0]["cmd"]
    assert "--ssid-hex %s" % AP_HEX_INJECTION in cmd
    assert data["effect"][0]["expect_stdout"] == \
        "^ap: started ssid_len=30 freq=5220$"


def test_the_lookalike_scenario_beacons_the_lookalike_name(scenarios):
    data = _scan(scenarios, "p-ow-wifiscan-02-lookalike")
    cmd = data["effect"][0]["cmd"]
    assert "--ssid-hex %s" % AP_HEX_LOOKALIKE in cmd
    assert data["effect"][0]["expect_stdout"] == \
        "^ap: started ssid_len=15 freq=5220$"


def test_the_radio0_scenario_starts_no_access_point(scenarios):
    """radio0 carries no access point of ours, so the scenario has no effect:
    it proves the read of a radio that has no AP of its own, and that the
    rate limits of the two radios are independent."""
    data = _scan(scenarios, "p-ow-wifiscan-03-radio0-independent")
    assert not data.get("effect")


def test_a_scan_post_reads_the_router_over_the_key_lane(scenarios):
    data = _scan(scenarios, "p-ow-wifiscan-01-injection")
    posts = data["post"]
    assert len(posts) >= 2
    first = posts[0]
    assert first["device"] == "local"
    assert "read wifiscan radio1" in first["cmd"]
    assert "{pulsar_runner_key}" in first["cmd"]
    assert "sleep 4" in first["cmd"]
    assert "python3 -I" in first["cmd"]
    assert first["expect_stdout"].startswith("^wifiscan: results=")


def test_the_second_read_of_the_same_radio_is_rate_limited(scenarios):
    data = _scan(scenarios, "p-ow-wifiscan-01-injection")
    limited = [p for p in data["post"] if p.get("expect_rc") == 2]
    assert len(limited) == 1
    post = limited[0]
    assert "read wifiscan radio1" in post["cmd"]
    assert post["expect_stdout"] == "^error scan-rate-limited$"


def test_the_lookalike_post_runs_the_host_code(scenarios):
    """The pair (the router's own SSID, the seen one) is classified by the
    host's own module, and the post prints the rule and the channel only."""
    data = _scan(scenarios, "p-ow-wifiscan-02-lookalike")
    post = data["post"][0]
    cmd = post["cmd"]
    assert "newton_mcp" in cmd
    assert "wifiscan" in cmd
    assert "scans" in cmd
    assert "{repo_root}/mcp" in cmd
    assert post["expect_stdout"] == "^lookalike: rule=homoglyph channel=44$"


def test_the_radio0_scenario_reads_both_radios(scenarios):
    data = _scan(scenarios, "p-ow-wifiscan-03-radio0-independent")
    cmds = [p["cmd"] for p in data["post"]]
    assert any("read wifiscan radio1" in c for c in cmds)
    assert sum("read wifiscan radio0" in c for c in cmds) == 2
    limited = [p for p in data["post"] if p.get("expect_rc") == 2]
    assert len(limited) == 1
    assert "read wifiscan radio0" in limited[0]["cmd"]
    assert limited[0]["expect_stdout"] == "^error scan-rate-limited$"


# ---------- nothing of a neighbour is ever printed ----------

def _printed_text(cmd):
    """The literal text a cmd prints: its echo and printf lines."""
    out = []
    for line in cmd.splitlines():
        stripped = line.strip()
        if stripped.startswith("echo ") or stripped.startswith("printf "):
            out.append(stripped)
    return "\n".join(out)


@pytest.mark.parametrize("name", PULSAR_SCANS)
def test_no_scan_post_prints_a_bssid_or_a_foreign_ssid(scenarios, name):
    """The posts print counts and rules: never an address of a neighbour and
    never a name of a neighbour.  Only the lab's own newton-test names may
    appear, and only as the names they are (the SSIDs themselves travel as
    hex)."""
    data = _scan(scenarios, name)
    for i, post in enumerate(data.get("post", [])):
        text = _printed_text(post["cmd"])
        assert not BSSID_RE.search(text), (name, i, text)
        for token in SSID_RE.findall(text):
            assert token.startswith("newton-test"), (name, i, token)


@pytest.mark.parametrize("name", PULSAR_SCANS)
def test_no_scan_scenario_file_carries_a_literal_bssid(scenarios, name):
    text = (SCEN_DIR / (name + ".toml")).read_text()
    assert not BSSID_RE.search(text), name


# ---------- the lab-r1 scenario: a router with no radio ----------

def test_the_lab_r1_scenario_reads_a_radio_that_is_not_there(lab_scenarios):
    data = lab_scenarios["ev-wifiscan-no-radio"]
    assert data["target"] == "lab-r1"
    assert data["reset"] == ["lab-r1"]
    assert data["expect"] == "none"
    posts = data["post"]
    assert len(posts) >= 3
    refused = posts[0]
    assert "read wifiscan radio0" in refused["cmd"]
    assert refused.get("expect_rc") == 2
    assert refused["expect_stdout"] == "^error no-radio$"
    bad = [p for p in posts if p.get("expect_rc") == 2
           and p["expect_stdout"] in ("^error bad-arg 2$", "^error bad-character$")]
    assert len(bad) == 2
    assert any("read wifiscan radio0;id" in p["cmd"]
               and p["expect_stdout"] == "^error bad-character$" for p in bad)
    assert any("read wifiscan phy0" in p["cmd"]
               and p["expect_stdout"] == "^error bad-arg 2$" for p in bad)


def test_the_lab_r1_scenario_prints_no_bssid(lab_scenarios):
    data = lab_scenarios["ev-wifiscan-no-radio"]
    for i, post in enumerate(data["post"]):
        text = _printed_text(post["cmd"])
        assert not BSSID_RE.search(text), (i, text)


# ---------- the example: the steps, the check and the var ----------

def test_the_example_defines_the_three_ap_steps(example):
    steps = example["steps"]
    for name in ("wifi_ap_injection", "wifi_ap_lookalike", "wifi_ap_stop"):
        assert name in steps, name
        assert steps[name]["device"] == "lab-wifi"
        assert steps[name].get("description"), name
    assert "--ssid-hex %s" % AP_HEX_INJECTION in \
        steps["wifi_ap_injection"]["cmd"]
    assert "--ssid-hex %s" % AP_HEX_LOOKALIKE in \
        steps["wifi_ap_lookalike"]["cmd"]
    for name in ("wifi_ap_injection", "wifi_ap_lookalike"):
        assert "--freq %d" % AP_FREQ in steps[name]["cmd"]
    assert "ap stop" in steps["wifi_ap_stop"]["cmd"]


def test_the_ap_steps_run_the_helper_as_root(example):
    for name in ("wifi_ap_injection", "wifi_ap_lookalike", "wifi_ap_stop"):
        cmd = example["steps"][name]["cmd"]
        assert cmd.strip().startswith("sudo newton-wifi.py ap "), name


def test_the_cleanup_step_stops_the_access_point(example):
    cmd = example["steps"]["wifi_cleanup"]["cmd"]
    assert "ap stop" in cmd
    assert "cleanup" in cmd


def test_p_panda_ap_off_is_a_lab_wifi_check(example):
    check = example["checks"]["p_panda_ap_off"]
    assert check["device"] == "lab-wifi"
    cmd = check["cmd"]
    assert "wpa_supplicant" in cmd
    assert "iw dev" in cmd
    assert "type ap" in cmd
    assert "type managed" in cmd
    assert check["expect_stdout"].startswith("^p_panda_ap_off: ")
    assert check.get("description")


def test_the_repo_root_var_is_provided(example):
    """The look-alike post imports the host's own module out of the
    checkout, so the runner has to hand the scenario the path of the
    checkout."""
    var = example["vars"]["repo_root"]
    assert var["device"] == "local"
    assert var["cmd"]
    assert var.get("secret", False) is False


def test_the_helper_the_example_installs_is_the_one_in_the_repo(example):
    """The install step heredocs the helper into the VM: the two copies have
    to be the same bytes, or the VM runs something the tests never saw."""
    cmd = example["steps"]["wifi_script_install"]["cmd"]
    lines = cmd.splitlines()
    start = None
    for i, line in enumerate(lines):
        if re.search(r"<<'(\w+)'", line) and "newton-wifi" in line:
            start = i + 1
            delim = re.search(r"<<'(\w+)'", line).group(1)
            break
    assert start is not None
    body = []
    for line in lines[start:]:
        if line == delim:
            break
        body.append(line)
    assert "\n".join(body) + "\n" == HELPER.read_text()
