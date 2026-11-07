"""The Pulsar Wi-Fi scenarios: lab/scenarios-pulsar/p-ow-wifi-0*.toml and
p-ev-09-wifi-radio.toml, the lab-wifi device and the wifi steps/checks/vars in
lab/pulsar.example.toml, and the key guard that keeps a literal PSK out of the
whole of lab/.

Everything here is offline: files in the repo and the helper's argparse
parser, no router, no VM, no network.
"""
from __future__ import annotations

import hashlib
import io
import re
import shlex
import sys
import tomllib
from pathlib import Path

import pytest

import newton_lab_test as nl

LAB_DIR = Path(__file__).resolve().parent.parent
EXAMPLE = LAB_DIR / "pulsar.example.toml"
SCEN_DIR = LAB_DIR / "scenarios-pulsar"
HELPER = LAB_DIR / "wifi" / "newton-wifi.py"
README = SCEN_DIR / "README.md"

WIFI_SCENARIOS = (
    "p-ow-wifi-01-sae",
    "p-ow-wifi-02-sae-mixed",
    "p-ow-wifi-03-wps-off",
    "p-ow-wifi-04-hidden",
    "p-ow-wifi-05a-isolate-off",
    "p-ow-wifi-05b-isolate-on",
    "p-ev-09-wifi-radio",
)
ISOLATE_PAIR = ("p-ow-wifi-05a-isolate-off", "p-ow-wifi-05b-isolate-on")
HELPER_PATH = "/usr/local/bin/newton-wifi.py"
PSK_PLACEHOLDER = "{wifi_psk}"


def _load_helper():
    import importlib.util
    spec = importlib.util.spec_from_file_location("newton_wifi", HELPER)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["newton_wifi"] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def helper():
    assert HELPER.is_file(), f"{HELPER} is missing"
    return _load_helper()


@pytest.fixture(scope="module")
def example():
    return tomllib.loads(EXAMPLE.read_text())


@pytest.fixture(scope="module")
def scenarios():
    out = {}
    for path in sorted(SCEN_DIR.glob("*.toml")):
        out[path.stem] = tomllib.loads(path.read_text())
    return out


def _wifi(scenarios, name):
    assert name in scenarios, f"{name} is missing from {SCEN_DIR}"
    return scenarios[name]


# ---------- the helper copy the step installs ----------

def _heredoc_text(cmd: str) -> str:
    """The text between the heredoc's opening line and its delimiter, the way
    the shell would feed it: every line up to (not including) the delimiter."""
    lines = cmd.splitlines()
    start = None
    for i, line in enumerate(lines):
        m = re.search(r"<<'(\w+)'", line)
        if m and "newton-wifi" in line:
            start = i + 1
            delim = m.group(1)
            break
    assert start is not None, f"no heredoc into newton-wifi.py in:\n{cmd}"
    out = []
    for line in lines[start:]:
        if line == delim:
            return "\n".join(out) + "\n"
        out.append(line)
    raise AssertionError(f"the heredoc to newton-wifi.py is never closed:\n{cmd}")


def test_the_install_step_heredocs_the_helper_byte_for_byte(example, helper):
    """The step that reaches lab-wifi writes lab/wifi/newton-wifi.py as
    /usr/local/bin/newton-wifi.py. If the two ever drift, the VM would run
    something the tests never saw."""
    step = example["steps"]["wifi_script_install"]
    assert step["device"] == "lab-wifi"
    assert _heredoc_text(step["cmd"]) == HELPER.read_text()


def test_the_install_step_writes_it_root_owned_0755(example):
    cmd = example["steps"]["wifi_script_install"]["cmd"]
    assert "/usr/local/bin/newton-wifi.py" in cmd
    assert re.search(r"sudo\s+install\b[^\n]*(?:^|\s)-m\s+0?755\b", cmd), cmd
    assert re.search(r"(?:^|\s)-o\s+root\b", cmd), cmd
    assert re.search(r"(?:^|\s)-g\s+root\b", cmd), cmd
    assert "-m 0755" in cmd


def test_the_install_step_parses_the_copy_it_writes(example):
    cmd = example["steps"]["wifi_script_install"]["cmd"]
    assert "ast.parse" in cmd and "-s " in cmd


# ---------- the example: device, vars, steps, checks ----------

def test_lab_wifi_device_is_defined(example):
    dev = example["devices"]["lab-wifi"]
    assert dev["vmid"] == 9107
    assert dev["host"] == "10.109.0.51"
    assert dev["user"] == "labuser"
    assert dev["snapshot"] == "baseline-wifi"
    assert dev["settle_cmd"] == example["devices"]["lab-client"]["settle_cmd"]


def test_lab_wifi_is_a_vm_not_a_physical_device(example):
    dev = example["devices"]["lab-wifi"]
    for physical_only in ("kind", "lab", "board_name", "admin_key",
                          "baseline_backup", "known_hosts"):
        assert physical_only not in dev, physical_only


def test_the_wifi_psk_is_a_secret_var_read_from_the_lab_host(example):
    var = example["vars"]["wifi_psk"]
    assert var["secret"] is True
    assert var["device"] == "local"
    assert var["cmd"] == "cat ~/.config/newton/pulsar/wifi-psk"


def test_the_key_file_path_is_a_var_of_its_own(example):
    """The path (not the key) is what a post greps with -f, and a scenario
    may not name a file under ~/.config, so it reaches the runner as a var."""
    var = example["vars"]["wifi_psk_file"]
    assert var["device"] == "local"
    assert var["cmd"] == "echo ~/.config/newton/pulsar/wifi-psk"
    assert var.get("secret", False) is False


def test_the_psk_var_and_the_path_var_name_the_same_file(example):
    read = example["vars"]["wifi_psk"]["cmd"]
    echo = example["vars"]["wifi_psk_file"]["cmd"]
    assert echo.startswith("echo ")
    assert read == "cat " + echo[len("echo "):]


def test_the_bssid_var_is_read_from_the_routers_phy1(example):
    var = example["vars"]["p_wifi_bssid"]
    assert var["device"] == "pulsar"
    assert var["cmd"] == "cat /sys/class/ieee80211/phy1/macaddress"
    assert var.get("secret", False) is False


def test_the_wifi_steps_are_defined(example):
    steps = example["steps"]
    assert steps["wifi_script_install"]["device"] == "lab-wifi"
    assert steps["wifi_key_install"]["device"] == "local"
    assert steps["wifi_prep"]["device"] == "lab-wifi"
    assert steps["wifi_cleanup"]["device"] == "lab-wifi"
    for name in ("wifi_script_install", "wifi_key_install", "wifi_prep",
                 "wifi_cleanup", "wifi_ap_injection", "wifi_ap_lookalike",
                 "wifi_ap_stop"):
        assert steps[name].get("description"), name


def test_the_key_install_step_pushes_the_key_over_stdin(example):
    """The key goes to the VM on stdin, never in argv and never in a var or a
    result: the cmd reads the local file and redirects it into sudo sh."""
    cmd = example["steps"]["wifi_key_install"]["cmd"]
    assert "sudo" in cmd
    assert "/run/newton-psk" in cmd
    assert re.search(r"<\s*\{wifi_psk_file\}", cmd), cmd
    assert "umask 077" in cmd or "umask 0077" in cmd
    assert re.search(r"cat\s*>\s*/run/newton-psk", cmd)
    # no shell word splitting of the key, no command substitution of it
    assert "$(cat" not in cmd and "`cat" not in cmd


def test_the_key_install_step_sshes_like_the_runner_sshes_to_a_vm(example):
    cmd = example["steps"]["wifi_key_install"]["cmd"]
    assert "$LAB_SSH_KEY" in cmd and "$LAB_SSH_PROXY" in cmd
    assert "{lab_wifi_user}@10.109.0.51" in cmd
    for option in ("BatchMode=yes", "IdentitiesOnly=yes", "ConnectTimeout=8"):
        assert option in cmd, option


def test_prep_and_cleanup_run_the_helper_as_root(example):
    assert example["steps"]["wifi_prep"]["cmd"].strip() == \
        "sudo newton-wifi.py prep"
    cleanup = example["steps"]["wifi_cleanup"]["cmd"]
    assert "sudo newton-wifi.py ap stop" in cleanup
    assert "sudo newton-wifi.py cleanup" in cleanup


def test_p_radios_off_is_a_pulsar_check(example):
    check = example["checks"]["p_radios_off"]
    assert check["device"] == "pulsar"
    assert "wireless.default_radio1.disabled" in check["cmd"]
    assert "wifi status" in check["cmd"]
    assert check["expect_stdout"]
    assert check.get("description")


def test_p_radios_off_requires_both_radios_off_and_no_interface(example):
    """disabled=1 for radio1 AND every `interfaces` list in `wifi status` empty
    (there is one per radio, so at least two) AND the stock ssid: a radio that
    is disabled but still carries an interface is not off."""
    cmd = example["checks"]["p_radios_off"]["cmd"]
    assert "wireless.default_radio1.disabled" in cmd
    assert "wifi status" in cmd
    assert '"interfaces"' in cmd
    assert cmd.count('"interfaces"') >= 2, "counted and compared, not grepped once"
    assert re.search(r"=\s*1\b", cmd)
    assert "OpenWrt" in cmd


def test_p_radios_off_prints_one_fixed_line(example):
    check = example["checks"]["p_radios_off"]
    # one stdout line; every failure goes to stderr through fail()
    assert len([ln for ln in check["cmd"].splitlines()
                if ln.strip().startswith("echo ")]) == 1
    assert check["expect_stdout"].startswith("^p_radios_off: ")


def test_p_wifi_client_ready_is_a_lab_wifi_check(example):
    check = example["checks"]["p_wifi_client_ready"]
    assert check["device"] == "lab-wifi"
    assert check["cmd"].strip() == "sudo newton-wifi.py prep"
    assert check["expect_stdout"] == "^panda "


def test_no_step_check_post_or_effect_names_the_secret_var(example, scenarios):
    """The runner refuses a secret var outside the batch (it would travel in
    ssh argv); the example keeps that true by construction, and the only
    place the placeholder appears is a scenario batch."""
    texts = []
    for table in ("steps", "checks"):
        for name, spec in example[table].items():
            texts.append((f"[{table}.{name}]", spec["cmd"]))
    for name, data in scenarios.items():
        for i, post in enumerate(data.get("post", [])):
            texts.append((f"{name} [[post]] #{i}", post["cmd"]))
        for i, effect in enumerate(data.get("effect", [])):
            texts.append((f"{name} [[effect]] #{i}", effect["cmd"]))
    bad = [where for where, cmd in texts if PSK_PLACEHOLDER in cmd]
    assert not bad, bad


# ---------- the five scenarios ----------

@pytest.mark.parametrize("name", WIFI_SCENARIOS)
def test_a_wifi_scenario_targets_pulsar_and_resets_it_both_ends(scenarios, name):
    data = _wifi(scenarios, name)
    assert data["target"] == "pulsar"
    assert data["reset"] == ["pulsar"]
    assert data["reset_after"] == ["pulsar"]


@pytest.mark.parametrize("name", WIFI_SCENARIOS)
def test_a_wifi_scenario_checks_the_radios_after_its_reset_after(scenarios,
                                                                  example,
                                                                  name):
    """The radio is on while the scenario runs and must be off once the
    reset_after has restored Pulsar: p_radios_off is the check that says so,
    and it can only run there (the runner's own regression list runs before
    the reset_after, where the radio is on by design)."""
    data = _wifi(scenarios, name)
    assert data["after_reset"] == ["p_radios_off"]
    assert "p_radios_off" in example["checks"]


@pytest.mark.parametrize("name", WIFI_SCENARIOS)
def test_a_wifi_scenario_is_approved_confirmed_and_gives_itself_time(scenarios,
                                                                    name):
    data = _wifi(scenarios, name)
    assert data["expect"] == "confirmed"
    assert data["approval"] is True
    assert data["timeout"] >= 180


@pytest.mark.parametrize("name", WIFI_SCENARIOS)
def test_a_wifi_scenario_installs_the_helper_the_key_and_preps(scenarios, name):
    data = _wifi(scenarios, name)
    assert data["setup"] == ["wifi_script_install", "wifi_key_install",
                             "wifi_prep"]
    assert data["cleanup"] == ["wifi_cleanup"]


@pytest.mark.parametrize("name", WIFI_SCENARIOS)
def test_a_wifi_scenario_regresses_the_pulsar_baseline(scenarios, example, name):
    """Every pulsar check that does not need a step the wifi scenarios do not
    run. portfwd needs portfwd_on, which no wifi scenario sets up, so it is
    left out; p_radios_off cannot be here either -- this list runs as the
    BEFORE and AFTER probes, both before reset_after, where the radio is on
    by design -- so it runs from after_reset instead (see the README)."""
    data = _wifi(scenarios, name)
    reg = data["regression"]
    default = example["regression"]["default"]
    assert isinstance(reg, list)
    assert "portfwd" not in reg
    assert "p_radios_off" not in reg
    assert reg == [c for c in default if c != "portfwd"]


@pytest.mark.parametrize("name", WIFI_SCENARIOS)
def test_a_wifi_scenario_uses_the_secret_psk_only_in_the_batch(scenarios, name):
    data = _wifi(scenarios, name)
    assert PSK_PLACEHOLDER in data["batch"]
    everywhere = [data["batch"]]
    for post in data.get("post", []):
        everywhere.append(post["cmd"])
    for effect in data.get("effect", []):
        everywhere.append(effect["cmd"])
    for probe in data.get("probes", []):
        everywhere.extend(probe)
    for text in everywhere[1:]:
        assert PSK_PLACEHOLDER not in text, text


@pytest.mark.parametrize("name", WIFI_SCENARIOS)
def test_a_wifi_scenario_probes_the_wlan_interface(scenarios, name):
    data = _wifi(scenarios, name)
    assert ["iface-field", "wlan", "up", "true"] in data["probes"]


@pytest.mark.parametrize("name", WIFI_SCENARIOS)
def test_a_wifi_scenario_batch_is_the_documented_one(scenarios, name):
    data = _wifi(scenarios, name)
    batch = data["batch"]
    assert "set network.wlan=interface" in batch
    assert "set network.wlan.proto='static'" in batch
    assert "set network.wlan.ipaddr='192.168.152.1'" in batch
    assert "set network.wlan.netmask='255.255.255.0'" in batch
    assert "set network.wlan.device" not in batch, "wlan is unnumbered"
    assert "set dhcp.wlan=dhcp" in batch
    assert "set dhcp.wlan.interface='wlan'" in batch
    assert "set dhcp.wlan.start='100'" in batch
    assert "set dhcp.wlan.limit='50'" in batch
    assert "set dhcp.wlan.leasetime='1h'" in batch
    assert "set firewall.wlz=zone" in batch
    assert "set firewall.wlz.name='wlz'" in batch
    assert "set firewall.wlz.network='wlan'" in batch
    assert "set firewall.wlz.input='ACCEPT'" in batch
    assert "set firewall.wlz.output='ACCEPT'" in batch
    assert "set firewall.wlz.forward='ACCEPT'" in batch
    assert "set firewall.wlz_wan=forwarding" in batch
    assert "set firewall.wlz_wan.src='wlz'" in batch
    assert "set firewall.wlz_wan.dest='wan'" in batch
    assert "set wireless.radio1.country='US'" in batch
    assert "set wireless.radio1.channel='36'" in batch
    assert "set wireless.radio1.htmode='HE20'" in batch
    assert "set wireless.radio1.txpower='3'" in batch
    assert "set wireless.default_radio1.disabled='0'" in batch
    assert "set wireless.default_radio1.network='wlan'" in batch
    # the key line is the placeholder and the ssid is this scenario's own
    key_lines = [ln for ln in batch.splitlines()
                 if ln.startswith("set wireless.default_radio1.key=")]
    assert key_lines == [f"set wireless.default_radio1.key='{PSK_PLACEHOLDER}'"]


@pytest.mark.parametrize("name", WIFI_SCENARIOS)
def test_a_wifi_scenario_edits_the_existing_iface_not_a_new_one(scenarios, name):
    """default_radio1 already exists in the baseline, so the batch edits it:
    a `set wireless.X=wifi-iface` line would create a second interface."""
    data = _wifi(scenarios, name)
    assert "set wireless.default_radio1=wifi-iface" not in data["batch"]
    assert "=wifi-iface" not in data["batch"]


@pytest.mark.parametrize("name", WIFI_SCENARIOS)
def test_a_wifi_scenario_has_a_description(scenarios, name):
    data = _wifi(scenarios, name)
    assert len(data["description"]) > 200, name


# ---------- the effects: only the helper's own subcommands and flags ----------

def _effect_argv(effect):
    cmd = effect["cmd"].strip()
    assert cmd.startswith("sudo " + HELPER_PATH + " "), cmd
    return shlex.split(cmd[len("sudo " + HELPER_PATH + " "):])


@pytest.mark.parametrize("name", WIFI_SCENARIOS)
def test_every_effect_is_the_helper_on_lab_wifi_with_the_pinned_bssid(
        scenarios, name):
    data = _wifi(scenarios, name)
    effects = data.get("effect", [])
    assert effects
    for effect in effects:
        assert effect["device"] == "lab-wifi"
        argv = _effect_argv(effect)
        assert "--bssid" in argv, argv
        assert argv[argv.index("--bssid") + 1] == "{p_wifi_bssid}", argv
        assert "--freq" in argv, argv
        assert argv[argv.index("--freq") + 1] == "5180", argv
        assert effect["expect_stdout"], effect["cmd"]


@pytest.mark.parametrize("name", WIFI_SCENARIOS)
def test_every_effect_cmd_parses_as_a_helper_invocation(scenarios, helper,
                                                        name):
    data = _wifi(scenarios, name)
    for effect in data.get("effect", []):
        ns = helper.build_parser().parse_args(_effect_argv(effect))
        assert ns.func.__name__ in ("cmd_monitor", "cmd_client", "cmd_prep",
                                    "cmd_cleanup", "cmd_pair"), ns.func.__name__


@pytest.mark.parametrize("name", WIFI_SCENARIOS)
def test_every_effect_summary_regex_matches_the_helper_summary(scenarios,
                                                               helper, name):
    """The expect_stdout of each effect is the helper's own summary line: a
    wrong regex would pass for the wrong reason or fail on a good run."""
    data = _wifi(scenarios, name)
    for effect in data.get("effect", []):
        ns = helper.build_parser().parse_args(_effect_argv(effect))
        if ns.func.__name__ == "cmd_monitor":
            # a monitor effect states both MFP bits, so the summary it is
            # matched against is derived from the scenario and not guessed
            assert ns.expect_mfpc is not None and ns.expect_mfpr is not None
            facts = _monitor_facts(ns, data["batch"])
            line = helper.summarise(**facts)
        elif ns.func.__name__ == "cmd_client":
            if ns.expect_fail:
                line = helper.expected_fail_line("SCANNING")
            else:
                # measured live: a completed association has the SSID in the scan
                # results whether the SSID was hidden or not
                line = helper.client_line("COMPLETED", "192.168.152.100", True, 1)
        elif ns.func.__name__ == "cmd_pair":
            line = _pair_facts(ns, helper)
        else:
            line = "panda enx02000000000x phy2"
        assert re.search(effect["expect_stdout"], line), (effect["cmd"], line)


def _pair_facts(ns, helper):
    """The pair line a scenario's own expectation is matched against: the two
    stations completed, the gateway answered, and the cross ping returned what
    the --expect-cross it was given means (all of --count, or none)."""
    received = ns.count if ns.expect_cross == "reachable" else 0
    return helper.pair_line("COMPLETED", "COMPLETED", True, received, ns.count)


def _monitor_facts(ns, batch):
    """A monitor fact set that satisfies every expectation the scenario gives.

    The SSID is the one the batch configured, unless the effect expects an empty
    one (the hidden case), and the cipher set is what the effect expects or the
    default CCMP. Neither is guessed from elsewhere in the repo."""
    akm = [int(a) for a in ns.expect_akm.split(",")] if ns.expect_akm else [8]
    configured = re.search(r"wireless\.default_radio1\.ssid='([^']*)'", batch)
    assert configured, "the batch must set the SSID the monitor prints"
    ssid = b"" if ns.expect_ssid_empty else (ns.expect_ssid or configured.group(1)).encode()
    ciphers = (ns.expect_rsn_ciphers or "ccmp").split(",")
    return {"beacons": max(ns.min_beacons, 5), "ssid": ssid, "akm": akm,
            "mfpc": ns.expect_mfpc if ns.expect_mfpc is not None else 1,
            "mfpr": ns.expect_mfpr if ns.expect_mfpr is not None else 1,
            "wps": bool(ns.expect_wps), "ciphers": ciphers,
            "neighbours": 0, "other_frames": 0, "channels": 1}


# ---------- the five scenarios, one by one ----------

def test_wifi_01_sae(scenarios):
    data = _wifi(scenarios, "p-ow-wifi-01-sae")
    assert "set wireless.default_radio1.ssid='newton-test'" in data["batch"]
    assert "set wireless.default_radio1.encryption='sae'" in data["batch"]
    assert "set wireless.default_radio1.ieee80211w='2'" in data["batch"]
    monitor, sae = [_effect_argv(e) for e in data["effect"]]
    assert monitor[0] == "monitor" and "--expect-akm" in monitor
    assert monitor[monitor.index("--expect-akm") + 1] == "8"
    assert monitor[monitor.index("--expect-mfpc") + 1] == "1"
    assert monitor[monitor.index("--expect-mfpr") + 1] == "1"
    assert "--expect-no-wps" in monitor
    assert sae[0] == "client" and sae[1] == "--mode" and sae[2] == "sae"
    assert "--expect-fail" not in sae
    # the WPA2-only client that must NOT associate is a post (see the test below)
    psk = [p for p in data["post"] if "--expect-fail" in p["cmd"]]
    assert len(psk) == 1
    assert psk[0]["device"] == "lab-wifi"
    argv = _effect_argv(psk[0])
    assert argv[0] == "client" and argv[argv.index("--mode") + 1] == "psk"
    assert argv[argv.index("--ieee80211w") + 1] == "0"
    assert argv[argv.index("--secs") + 1] == "25"
    assert "--expect-fail" in argv


@pytest.mark.parametrize("name", WIFI_SCENARIOS)
def test_no_effect_is_one_that_passes_before_the_change(scenarios, helper, name):
    """The runner runs every effect as a BEFORE probe with want=fail, and
    refuses an effect that already passes ("already passes before apply; it
    cannot detect the change"). An --expect-fail client passes before the change
    too (there is no AP yet), so it can only be a post, which runs after."""
    for effect in _wifi(scenarios, name).get("effect", []):
        ns = helper.build_parser().parse_args(_effect_argv(effect))
        assert not getattr(ns, "expect_fail", False), effect["cmd"]


def test_wifi_02_sae_mixed(scenarios):
    data = _wifi(scenarios, "p-ow-wifi-02-sae-mixed")
    assert "set wireless.default_radio1.encryption='sae-mixed'" in data["batch"]
    assert "set wireless.default_radio1.ieee80211w='1'" in data["batch"]
    monitor, sae, psk = [_effect_argv(e) for e in data["effect"]]
    assert monitor[monitor.index("--expect-akm") + 1] == "2,6,8"
    assert monitor[monitor.index("--expect-mfpc") + 1] == "1"
    assert monitor[monitor.index("--expect-mfpr") + 1] == "0"
    assert sae[sae.index("--mode") + 1] == "sae"
    assert psk[psk.index("--mode") + 1] == "psk"
    assert psk[psk.index("--ieee80211w") + 1] == "0"
    assert "--expect-fail" not in sae and "--expect-fail" not in psk


def test_wifi_03_wps_off_says_what_it_proves(scenarios):
    data = _wifi(scenarios, "p-ow-wifi-03-wps-off")
    assert "set wireless.default_radio1.encryption='sae-mixed'" in data["batch"]
    assert "wps_pushbutton" not in data["batch"], \
        "del of a missing option is not a noop: uci batch writes to stderr and " \
            "owrt-safe-apply.sh rejects the whole batch"
    monitor = _effect_argv(data["effect"][0])
    assert monitor[0] == "monitor" and "--expect-no-wps" in monitor
    posts = [p for p in data["post"] if "wps_pushbutton" in p["cmd"]]
    assert len(posts) == 1, "the post that wps_pushbutton is unset"
    assert posts[0]["device"] == "pulsar"


def test_wifi_03_wps_off_description_names_the_build_not_the_config(scenarios):
    desc = _wifi(scenarios, "p-ow-wifi-03-wps-off")["description"]
    assert "wpad-basic-mbedtls" in desc
    assert "wps_state" in desc and "wps_pin" in desc
    assert "follow-up" in desc
    assert "wpad-mbedtls" in desc
    assert "package" in desc and "world" in desc
    # it must state plainly what the beacon proves, and what it does not
    assert "not that a config option turned WPS off" in desc


def test_wifi_04_hidden(scenarios):
    data = _wifi(scenarios, "p-ow-wifi-04-hidden")
    assert "set wireless.default_radio1.encryption='sae-mixed'" in data["batch"]
    assert "set wireless.default_radio1.hidden='1'" in data["batch"]
    monitor = _effect_argv(data["effect"][0])
    assert monitor[0] == "monitor"
    assert "--expect-ssid-empty" in monitor
    assert monitor[monitor.index("--min-beacons") + 1] == "5"
    client = _effect_argv(data["effect"][1])
    assert client[client.index("--mode") + 1] == "sae"
    assert "--scan-ssid" in client


def test_wifi_04_hidden_description_calls_hiding_cosmetic(scenarios):
    desc = _wifi(scenarios, "p-ow-wifi-04-hidden")["description"]
    assert "cosmetic" in desc
    assert "OW-WIFI-04" in desc and "do NOT use" in desc


def test_ev_09_wifi_radio(scenarios):
    data = _wifi(scenarios, "p-ev-09-wifi-radio")
    assert "set wireless.default_radio1.ssid='newton-test-ev'" in data["batch"]
    assert "set wireless.default_radio1.encryption='psk2'" in data["batch"]
    assert f"set wireless.default_radio1.key='{PSK_PLACEHOLDER}'" in data["batch"]
    monitor, client = [_effect_argv(e) for e in data["effect"]]
    assert monitor[monitor.index("--expect-akm") + 1] == "2"
    assert monitor[monitor.index("--expect-mfpc") + 1] == "0"
    assert client[client.index("--mode") + 1] == "psk"


def test_ev_09_wifi_radio_drops_the_no_radio_claims(scenarios):
    desc = _wifi(scenarios, "p-ev-09-wifi-radio")["description"]
    assert "rejected" not in desc
    assert "no radio" not in desc
    assert "config path only" not in desc
    assert "ev-09" in desc.lower() or "EV-09" in desc


# ---------- the isolate pair (OW-ZONE-03): p-ow-wifi-05a/05b ----------

def test_the_isolate_pair_is_two_scenarios(scenarios):
    for name in ISOLATE_PAIR:
        _wifi(scenarios, name)


@pytest.mark.parametrize("name,isolate,cross", [
    ("p-ow-wifi-05a-isolate-off", "0", "reachable"),
    ("p-ow-wifi-05b-isolate-on", "1", "blocked"),
])
def test_the_isolate_pair_sets_only_its_own_isolate_and_expectation(
        scenarios, name, isolate, cross):
    data = _wifi(scenarios, name)
    assert f"set wireless.default_radio1.isolate='{isolate}'" in data["batch"]
    # the batch is the sae-mixed one the prototype ran against (measured)
    assert "set wireless.default_radio1.encryption='sae-mixed'" in data["batch"]
    assert "set wireless.default_radio1.ieee80211w='1'" in data["batch"]
    assert "set wireless.default_radio1.ssid='newton-test'" in data["batch"]
    effects = data["effect"]
    assert len(effects) == 1
    argv = _effect_argv(effects[0])
    assert argv[0] == "pair"
    assert argv[argv.index("--expect-cross") + 1] == cross
    assert argv[argv.index("--ieee80211w") + 1] == "1"
    assert argv[argv.index("--secs") + 1] == "40"
    assert effects[0]["timeout"] == 200


@pytest.mark.parametrize("name,isolate", [("p-ow-wifi-05a-isolate-off", "0"),
                                          ("p-ow-wifi-05b-isolate-on", "1")])
def test_the_isolate_pair_reads_its_value_back_off_the_router(scenarios, name,
                                                              isolate):
    data = _wifi(scenarios, name)
    posts = [p for p in data.get("post", [])
             if "wireless.default_radio1.isolate" in p["cmd"]]
    assert len(posts) == 1
    post = posts[0]
    assert post["device"] == "pulsar"
    assert "uci -q get wireless.default_radio1.isolate" in post["cmd"]
    assert post["expect_stdout"]
    assert PSK_PLACEHOLDER not in post["cmd"]


def test_the_isolate_pair_differs_in_exactly_the_isolate_value(scenarios):
    """One batch, one effect cmd, one post: the two scenarios are the same run
    with isolation off and on. Anything else that differs would be a second
    variable in a two-value proof."""
    a = _wifi(scenarios, "p-ow-wifi-05a-isolate-off")
    b = _wifi(scenarios, "p-ow-wifi-05b-isolate-on")
    for key in ("target", "reset", "reset_after", "after_reset", "approval",
                "expect", "setup", "cleanup", "regression", "probes", "timeout"):
        assert a[key] == b[key], key
    assert a["batch"].splitlines() != b["batch"].splitlines()
    pairs = [(x, y) for x, y in zip(a["batch"].splitlines(),
                                    b["batch"].splitlines()) if x != y]
    assert pairs == [("set wireless.default_radio1.isolate='0'",
                      "set wireless.default_radio1.isolate='1'")]
    assert len(a["batch"].splitlines()) == len(b["batch"].splitlines())
    assert a["effect"][0]["timeout"] == b["effect"][0]["timeout"]
    assert a["effect"][0]["device"] == b["effect"][0]["device"]


def test_the_isolate_pair_gives_itself_more_than_the_other_wifi_scenarios(
        scenarios):
    """The pair waits on two associations and then on three pings, so it needs
    more of the scenario's own timeout than the one-client scenarios give."""
    for name in ISOLATE_PAIR:
        assert _wifi(scenarios, name)["timeout"] == 300


@pytest.mark.parametrize("name", ISOLATE_PAIR)
def test_the_pair_effect_cannot_pass_before_the_change(scenarios, helper, name):
    """The runner refuses an effect that already passes before the apply. Before
    the apply there is no AP at all, so neither station reaches COMPLETED: the
    line is a=SCANNING b=SCANNING gw=fail received=0/8, which fails the
    expectation of both scenarios - 05b's `blocked` included."""
    effect = _wifi(scenarios, name)["effect"][0]
    line = helper.pair_line("SCANNING", "SCANNING", False, 0, 8)
    assert not re.search(effect["expect_stdout"], line), (name, line)


def test_the_isolate_pair_descriptions_say_what_each_half_proves(scenarios):
    off = _wifi(scenarios, "p-ow-wifi-05a-isolate-off")["description"]
    on = _wifi(scenarios, "p-ow-wifi-05b-isolate-on")["description"]
    # 05a is the control: it shows the cross path works at all
    assert "OW-ZONE-03" in off
    assert "control" in off.lower()
    assert "reach each other" in off
    assert "gateway" in off
    # 05b is the measurement: isolation blocks station-to-station traffic
    assert "OW-ZONE-03" in on
    assert "isolation" in on.lower()
    assert "station-to-station" in on
    assert "gateway" in on
    for desc in (off, on):
        # the two stations are two vifs of the one Panda, each in its own VRF,
        # and the single-namespace method is why
        assert "vifs of the one" in desc
        assert "VRF" in desc
        assert "namespace" in desc


def test_ev_09_wifi_radio_greps_the_key_from_a_file_never_from_a_word(scenarios):
    """The key must not reach a command line: the posts grep with
    `grep -F -f FILE` (patterns from the file) and print only the count."""
    data = _wifi(scenarios, "p-ev-09-wifi-radio")
    posts = [p for p in data["post"] if "wifi_psk_file" in p["cmd"]]
    assert len(posts) >= 2, [p["cmd"] for p in data["post"]]
    for post in posts:
        assert "-F" in post["cmd"] and "-f {wifi_psk_file}" in post["cmd"]
        assert "-c" in post["cmd"], post["cmd"]
        assert post["expect_stdout"]
        for line in post["cmd"].splitlines():
            if "grep" in line:
                assert PSK_PLACEHOLDER not in line
                assert "{wifi_psk}" not in line
    # no post fetches the key into a shell variable either
    for post in data["post"]:
        assert "$(cat {wifi_psk_file}" not in post["cmd"], post["cmd"]


# ---------- the p-ev-08 iwinfo post ----------

def test_ev_08_iwinfo_post_is_corrected(scenarios):
    data = _wifi(scenarios, "p-ev-08-diagnostics-read")
    posts = [p for p in data["post"] if "read iwinfo" in p["cmd"]]
    assert len(posts) == 1
    post = posts[0]
    assert post["expect_rc"] == 0
    assert "newton-test" in post["cmd"], "an SSID in the output would mean an interface is up"
    assert "127" not in post["expect_stdout"], "iwinfo is not missing"
    assert "tool-missing" not in post["expect_stdout"]
    assert post["expect_stdout"].startswith("^iwinfo: ")
    assert "rc=0" in post["expect_stdout"]


def test_ev_08_says_iwinfo_exists(scenarios):
    """Measured 2026-10-22: /usr/bin/iwinfo is a ucode script on Pulsar and
    `read iwinfo` exits 0 with no output while no wireless interface exists.
    The old post claimed a missing binary and rc 127; the description may
    mention that only as the wrong thing it was."""
    data = _wifi(scenarios, "p-ev-08-diagnostics-read")
    text = data["description"]
    assert "/usr/bin/iwinfo" in text
    assert "no iwinfo binary" not in text
    assert "no wireless interface at all" in text
    assert "was factually wrong" in text
    header = Path(SCEN_DIR / "p-ev-08-diagnostics-read.toml").read_text()
    first = header.splitlines()[0]
    assert "/usr/bin/iwinfo" in first
    assert "no iwinfo binary" not in first
    assert "never true" in first


def test_ev_08_keeps_the_bad_arg_post(scenarios):
    data = _wifi(scenarios, "p-ev-08-diagnostics-read")
    bad = [p for p in data["post"] if "read ls" in p["cmd"]]
    assert len(bad) == 1 and bad[0]["expect_rc"] == 2


# ---------- the key guard ----------

# A `wireless.*.key=` or `sae_password=` line carrying a literal key. Only
# the {wifi_psk} placeholder is allowed, plus the values the repo itself
# defines: the helper's runtime template (%s) and this test's synthetic
# fixture. Anything else - a pasted PSK - is a failure.
KEY_LINE = re.compile(
    r"""(?:wireless\.[\w.\[\]-]*\.key|sae_password)\s*=\s*(['"])(.*?)\1""")
ALLOWED_KEY_VALUES = {
    "{wifi_psk}",          # the placeholder the runner substitutes
    "{PSK_PLACEHOLDER}",   # the tests above spell that placeholder by name
    "%s",                  # lab/wifi/newton-wifi.py: the runtime conf template
    "{FAKE_KEY}",          # lab/tests/test_wifi_helper.py: the test constant
    "EvMadeUpKey-7f3a91c2",  # the made-up key of lab/scenarios/everyday/ev-09,
                            # which exists so that scenario can prove it never
                            # shows up anywhere; not a real key
}
SKIP_DIRS = {".results", "__pycache__", ".git", ".venv"}


def _lab_files():
    for path in sorted(LAB_DIR.rglob("*")):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        yield path


def test_no_file_under_lab_carries_a_literal_wifi_key():
    bad = []
    for path in _lab_files():
        text = path.read_text(errors="replace")
        for lineno, line in enumerate(text.splitlines(), 1):
            m = KEY_LINE.search(line)
            if m and m.group(2) not in ALLOWED_KEY_VALUES:
                bad.append(f"{path.relative_to(LAB_DIR)}:{lineno}")
    assert not bad, f"a literal key on a wireless.*.key / sae_password line: {bad}"


# The two samples below are the guard's own test. Their lines are assembled
# from parts so that this file does not itself hold a line the guard would
# report (it is scanned like every other file under lab/).
SAMPLE_KEY_LINE = "".join(["set wireless.default_radio1", ".key='Real",
                           "PastedKey-1'"])
SAMPLE_SAE_LINE = "".join(['    sae_pass', 'word="Real', 'PastedKey-2"'])


def _values(line):
    m = KEY_LINE.search(line)
    return [m.group(2)] if m else []


def test_the_key_guard_catches_a_pasted_key(tmp_path):
    """The guard itself: plant a key on a wireless.*.key line in a file shaped
    like a scenario and the detector names it."""
    fake = tmp_path / "p-ow-wifi-xx.toml"
    fake.write_text("batch = '" + SAMPLE_KEY_LINE + "'\n")
    assert _values(SAMPLE_KEY_LINE) == ["RealPastedKey-1"]
    assert "RealPastedKey-1" not in ALLOWED_KEY_VALUES


def test_the_key_guard_catches_a_sae_password_literal(tmp_path):
    fake = tmp_path / "conf.txt"
    fake.write_text(SAMPLE_SAE_LINE + "\n")
    assert _values(SAMPLE_SAE_LINE) == ["RealPastedKey-2"]


def test_the_key_guard_allows_the_placeholder_and_the_template():
    assert _values("set wireless.default_radio1.key='{wifi_psk}'") == [
        "{wifi_psk}"]
    assert _values("        sae_password=\"%s\"") == ["%s"]


def test_the_example_has_one_live_wifi_psk_var(example):
    """The shape comment at the top of the example stays a comment; the real
    secret var is a live table below it."""
    live = [k for k, v in example["vars"].items() if v.get("secret")]
    assert live == ["wifi_psk"]
    assert "#   [vars.wifi_psk]" in EXAMPLE.read_text()


# ---------- p_radios_off placement ----------

def test_p_radios_off_is_defined_and_used_where_it_can_pass(scenarios, example):
    """The runner runs a scenario's regression as its BEFORE probes and its
    AFTER probes, both before reset_after, so a wifi scenario (whose radio is
    on after its apply) cannot carry p_radios_off in it: it would fail the
    AFTER probe. Each wifi scenario runs it from after_reset instead, on the
    far side of the reset that turns the radio off. p-ow-00-baseline keeps it
    in its regression as well, as the belt-and-braces BEFORE probe that opens
    a full run: it comes after the wifi scenarios' reset_after in the order
    and before the four that turn the radio on again."""
    assert "p_radios_off" in example["checks"]
    baseline = _wifi(scenarios, "p-ow-00-baseline")
    assert "p_radios_off" in baseline["regression"]
    for name in WIFI_SCENARIOS:
        data = _wifi(scenarios, name)
        assert "p_radios_off" not in data["regression"]
        assert data["after_reset"] == ["p_radios_off"]
    ordered = sorted(scenarios)
    here = ordered.index("p-ow-00-baseline")
    assert here > ordered.index("p-ev-09-wifi-radio")
    for name in ("p-ow-wifi-01-sae", "p-ow-wifi-02-sae-mixed",
                 "p-ow-wifi-03-wps-off", "p-ow-wifi-04-hidden"):
        assert here < ordered.index(name), name


def test_p_ow_00_baseline_regression_is_the_default_list_plus_radios_off(
        scenarios, example):
    reg = _wifi(scenarios, "p-ow-00-baseline")["regression"]
    assert reg == example["regression"]["default"] + ["p_radios_off"]


# ---------- the README ----------

def test_readme_lists_every_wifi_scenario():
    text = README.read_text()
    for name in WIFI_SCENARIOS:
        assert name in text, name
    assert "lab-wifi" in text and "9107" in text
    assert "wifi-psk" in text
    assert "ev-09" in text


def test_readme_records_the_follow_ups():
    text = README.read_text()
    assert "OW-ZONE-03" in text
    assert "wpad-mbedtls" in text
    assert "package" in text and "world" in text


def test_readme_records_the_isolate_pair_and_what_it_measured():
    """The pair is measured now, not a follow-up: both scenario names, the VRF
    method that made it possible, and both results (8/8 with isolation off, 0/8
    with it on)."""
    text = README.read_text()
    assert "OW-ZONE-03" in text
    for name in ISOLATE_PAIR:
        assert name in text, name
    assert "VRF" in text and "8/8" in text and "0/8" in text
    assert "Skipped by" not in text
    follow = text.split("Follow-ups:", 1)[1].split("\n## ", 1)[0]
    assert "OW-ZONE-03" not in follow, follow
    gaps = text.split("## Known gaps", 1)[1]
    assert "is the follow-up" not in gaps, gaps


def test_readme_says_the_two_lab_scenarios_left_are_not_ev_09(scenarios):
    text = README.read_text()
    gaps = text.split("## Known gaps", 1)[1]
    for line in gaps.splitlines():
        if "not ported" in line:
            assert "ev-09" not in line, line


def test_the_wifi_scenarios_validate_against_the_example(tmp_path, monkeypatch):
    """A last pass through the runner's own validation: every step, var, check
    and device the five scenarios name exists in the example, and no secret var
    is used outside a batch."""
    import io as _io
    import tarfile

    monkeypatch.setenv("HOME", str(tmp_path))
    home = tmp_path / ".config" / "newton" / "pulsar"
    home.mkdir(parents=True)
    for name in ("known-hosts", "admin-key", "change-key"):
        (home / name).write_text("x\n")
    (home / "wifi-psk").write_text("not-a-real-key\n")

    buf = _io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in (
                ("etc/config/network", b"synthetic\n"),
                ("etc/config/firewall", b"synthetic\n"),
                ("etc/config/system", b"synthetic\n"),
                ("etc/config/dropbear", b"synthetic\n"),
                ("etc/dropbear/authorized_keys", b"synthetic\n"),
                ("etc/newton/device-id", b"pulsar\n"),
                ("etc/newton/profile", b"lab\n")):
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            tf.addfile(ti, _io.BytesIO(data))
    archive = buf.getvalue()
    (home / "baseline.tar.gz").write_bytes(archive)

    path = tmp_path / "lab.toml"
    path.write_text(EXAMPLE.read_text().replace(
        "<sha256 of baseline.tar.gz>", hashlib.sha256(archive).hexdigest()))
    lab = nl.load_lab(path)
    assert nl.validate_scenarios(lab, nl.load_scenarios(SCEN_DIR)) == []
    assert "lab-wifi" in lab.devices
    assert nl.secret_var_names(lab) == {"wifi_psk"}

# ---------- p_radios_off run for real, against fake uci/wifi ----------

import os
import subprocess

_OFF_STATUS = ('{"radio0": {"up": true, "interfaces": [\n\n]},\n'
               ' "radio1": {"up": true, "interfaces": [\n\t\t\n\t]}}\n')
_UP_STATUS = ('{"radio0": {"up": true, "interfaces": [\n\n]},\n'
              ' "radio1": {"up": true, "interfaces": [\n {"section": "default_radio1", "ifname": "phy1-ap0"}\n]}}\n')


def _run_radios_off(example, tmp_path, *, disabled, ssid, status):
    """The check's own shell text, with `uci` and `wifi` replaced by scripts that
    answer from the recorded values. Returns (rc, stdout)."""
    fake = tmp_path / "bin"
    fake.mkdir()
    (fake / "uci").write_text(
        "#!/bin/sh\n"
        'case "$*" in\n'
        f'  *default_radio1.disabled*) echo {disabled};;\n'
        f'  *default_radio1.ssid*) echo {ssid};;\n'
        "esac\n")
    (fake / "wifi").write_text("#!/bin/sh\ncat <<'EOF'\n" + status + "EOF\n")
    for f in fake.iterdir():
        f.chmod(0o755)
    env = dict(os.environ, PATH=f"{fake}:{os.environ['PATH']}")
    proc = subprocess.run(["bash", "-c", example["checks"]["p_radios_off"]["cmd"]],
                          capture_output=True, text=True, env=env, timeout=20)
    return proc.returncode, proc.stdout


def test_p_radios_off_passes_on_the_recorded_off_state(example, tmp_path):
    rc, out = _run_radios_off(example, tmp_path, disabled=1, ssid="OpenWrt", status=_OFF_STATUS)
    assert rc == 0
    assert re.search(example["checks"]["p_radios_off"]["expect_stdout"], out)


@pytest.mark.parametrize("disabled,ssid,status,why", [
    (1, "OpenWrt", _UP_STATUS, "an interface is still up on radio1"),
    (0, "OpenWrt", _OFF_STATUS, "radio1 not disabled in uci"),
    (1, "newton-test", _OFF_STATUS, "the test ssid is still configured"),
    (1, "OpenWrt", "", "wifi status gave nothing: that proves nothing"),
])
def test_p_radios_off_fails_when_a_radio_is_left_up(example, tmp_path, disabled, ssid, status, why):
    rc, out = _run_radios_off(example, tmp_path, disabled=disabled, ssid=ssid, status=status)
    assert rc != 0, why
    assert not re.search(example["checks"]["p_radios_off"]["expect_stdout"], out), why


def test_wifi_key_install_pins_the_vm_host_key(example):
    cmd = example["steps"]["wifi_key_install"]["cmd"]
    assert "StrictHostKeyChecking=no" not in cmd and "/dev/null" not in cmd
    assert cmd.count("StrictHostKeyChecking=yes") == cmd.count("{lab_wifi_user}@10.109.0.51") >= 2
    assert cmd.count("UserKnownHostsFile={lab_wifi_known_hosts}") == cmd.count("{lab_wifi_user}@10.109.0.51")
    assert "lab_wifi_known_hosts" in example["vars"]
