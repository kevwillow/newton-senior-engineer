"""The Pulsar port must stay runnable from the repo: every step, var, check and
device that lab/scenarios-pulsar/*.toml reference is defined in
lab/pulsar.example.toml, and that file carries no secrets or machine paths."""
from __future__ import annotations

import hashlib
import io
import re
import tarfile
import os
from pathlib import Path

import pytest

import newton_lab_test as nl

LAB_DIR = Path(__file__).resolve().parent.parent
EXAMPLE = LAB_DIR / "pulsar.example.toml"
SCEN_DIR = LAB_DIR / "scenarios-pulsar"


def _synthetic_archive() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name in ("etc/config/network", "etc/config/firewall",
                     "etc/config/system", "etc/config/dropbear",
                     "etc/dropbear/authorized_keys", "etc/newton/device-id",
                     "etc/newton/profile"):
            data = {"etc/newton/device-id": b"pulsar\n",
                    "etc/newton/profile": b"lab\n"}.get(name, b"synthetic\n")
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


@pytest.fixture
def home(tmp_path, monkeypatch):
    """A HOME holding the files the example's placeholder paths name."""
    monkeypatch.setenv("HOME", str(tmp_path))
    d = tmp_path / ".config" / "newton" / "pulsar"
    d.mkdir(parents=True)
    for name in ("known-hosts", "admin-key", "change-key"):
        (d / name).write_text("x\n")
    (d / "baseline.tar.gz").write_bytes(_synthetic_archive())
    return tmp_path


@pytest.fixture
def example_lab(home, tmp_path):
    text = EXAMPLE.read_text().replace(
        "<sha256 of baseline.tar.gz>",
        hashlib.sha256(_synthetic_archive()).hexdigest())
    p = tmp_path / "lab.toml"
    p.write_text(text)
    return nl.load_lab(p)


@pytest.fixture
def scenarios():
    return nl.load_scenarios(SCEN_DIR)


def test_example_exists_and_scenarios_present(scenarios):
    assert EXAMPLE.is_file()
    assert len(scenarios) >= 60


def test_example_loads_and_defines_pulsar_as_physical(example_lab):
    dev = example_lab.devices["pulsar"]
    assert dev.kind == "physical"


def test_every_scenario_validates_against_the_example(example_lab, scenarios):
    assert nl.validate_scenarios(example_lab, scenarios) == []


def test_every_referenced_name_is_defined(example_lab, scenarios):
    steps, checks, devices = set(), set(), set()
    texts: list[str] = []
    for s in scenarios:
        steps.update(s.setup + s.cleanup)
        reg = s.regression
        if reg == "default":
            checks.update(example_lab.regression_default)
        elif isinstance(reg, list):
            checks.update(reg)
        checks.update(s.breaks)
        checks.update(s.breaks_password or ())
        devices.update(s.reset)
        devices.add(s.target)
        texts.append(s.batch)
        for p in s.post + s.effects:
            devices.add(p.device)
            texts.append(p.cmd)
    checks.update(example_lab.regression_default)
    assert steps and checks
    assert steps <= set(example_lab.steps), steps - set(example_lab.steps)
    assert checks <= set(example_lab.checks), checks - set(example_lab.checks)
    for n in steps:
        texts.append(example_lab.steps[n].cmd)
        devices.add(example_lab.steps[n].device)
    for n in checks:
        texts.append(example_lab.checks[n].cmd)
        devices.add(example_lab.checks[n].device)
    for v in example_lab.var_defs.values():
        devices.add(v["device"])
    devices.discard("local")
    assert devices <= set(example_lab.devices), devices - set(example_lab.devices)
    used = nl.used_placeholders(*texts)
    assert used <= set(example_lab.var_defs), used - set(example_lab.var_defs)


def test_example_has_every_step_var_and_check_the_port_was_run_with(example_lab):
    # the names the live Pulsar run used; losing one is drift
    for n in ("agent_masq_on", "reboot_watch_on", "portfwd_on", "http8080_on",
              "fw4_break_on", "sntp_on", "ssh_observer_start",
              # the VLAN lab LAN: lab-client's probe scripts and namespaces,
              # and the dualwan steps on lab-isp
              "tcpraw_on", "guest_ns_on", "iot_ns_on", "zone_probe_on",
              "dhcp_probe_on", "dhcp_probe_mac_on",
              "dw_wanhealth_install", "dw_isp_count_on"):
        assert n in example_lab.steps
    for n in ("fw_wan_zone", "fw_lan_zone", "fw_allow_ping", "p_wan_ip", "agent_ip",
              "p_wan2_ip", "client_lab_ip"):
        assert n in example_lab.var_defs
    for n in ("mgmt_ssh", "mgmt_ssh_pw", "mgmt_ssh_newton", "p_dns", "portfwd",
              "p_client_on_pulsar", "client_internet", "client_dns",
              "client_dhcp", "client_ext_dns", "client_dot", "client_isp_ssh"):
        assert n in example_lab.checks


def test_lab_client_is_on_pulsars_lab_lan(example_lab):
    """lab-client (VM 9105) is defined in the example and reset to the snapshot
    that has it on Pulsar's lab LAN (VLAN 151 on the WAN cable), and the check
    that proves it (its default route via 192.168.151.1 on eth0) is in the
    default regression, so every ported scenario runs it."""
    dev = example_lab.devices["lab-client"]
    assert dev.vmid == 9105
    assert dev.snapshot == "baseline-pulsar"
    assert "p_client_on_pulsar" in example_lab.regression_default


# A lab-r1 client-LAN literal that survived a port: 192.168.150.0/24 (the ported
# lab LAN is 192.168.151.0/24), lab-r1's management address, or one of its router
# devices (eth3 and the 802.1q sub-interfaces of the client LAN port). Only live
# lines are checked: comment lines and `description` fields are documentation the
# runner never executes, and a port's one-line `# PORT of ...` header (or the
# p_client_on_pulsar description, which names the address the wrong snapshot
# would restore) names the old literal on purpose. Every cmd, batch, probe and
# expect regex is checked.
_LAB_R1_CLIENT_LAN_LITERALS = (
    "192.168.150.", "10.109.0.11", "DHCPDISCOVER(eth3)", "eth3.30", "eth3.40",
)
_LAB_R1_TARGET = re.compile(
    r"""^\s*(target|device|reset)\s*=\s*.*["']lab-r1["']""")
_DOC_LINE = re.compile(r"^\s*(#|description\s*=)")


def test_no_lab_r1_client_lan_literals():
    files = sorted(SCEN_DIR.glob("*.toml")) + [EXAMPLE]
    bad = []
    for path in files:
        for lineno, line in enumerate(path.read_text().splitlines(), 1):
            if _DOC_LINE.match(line):
                continue
            if any(lit in line for lit in _LAB_R1_CLIENT_LAN_LITERALS):
                bad.append(f"{path.name}:{lineno}")
            if path != EXAMPLE and _LAB_R1_TARGET.search(line):
                bad.append(f"{path.name}:{lineno}")
    assert not bad, f"lab-r1 client LAN literals left: {bad}"


@pytest.mark.parametrize("line,matches", [
    ('device="lab-r1"', True),
    ("device = 'lab-r1'", True),
    ('reset = ["lab-r1"]', True),
    ('target = "lab-r1"', True),
    ('device = "lab-client"', False),
    ('# PORT of x. Changed: lab-r1 -> pulsar', False),
])
def test_lab_r1_target_regex_catches_variants(line: str, matches: bool):
    """The target regex catches every spelling of a lab-r1 device line and
    leaves the other devices and the `# PORT of` header alone."""
    assert bool(_LAB_R1_TARGET.search(line)) is matches, line


P6_PORTS = (
    "p-ev-01-static-lease-served",
    "p-ev-07-fw-user-block",
    "p-ow-dhcp-01-lab-pool-limit",
    "p-ow-fw-02-synflood-protect",
    "p-ow-fw-03-drop-invalid",
    "p-ow-log-02c-dnsmasq-logging-survives-logd-restart",
    "p-ow-log-02d-dnsmasq-logging-after-rollback",
    "p-ow-dns-06-force-lan-dns",
    "p-ow-dns-07-block-dot",
    "p-ow-dns-08-block-outbound-dns",
    "p-ow-zone-01-guest",
    "p-ow-zone-02-iot",
    "p-ow-v6-03-ipv6-off-client-lan",
    "p-dw-01-failover",
    "p-dw-02-failback",
    "p-dw-03-upstream-dead-no-service",
    "p-dw-04-no-flap",
    "p-dw-05-failover-ifdown",
)


def test_p6_ports_present(scenarios):
    """The VLAN-lab ports (through the VLAN lab LAN) are all loaded."""
    loaded = {s.name for s in scenarios}
    missing = [n for n in P6_PORTS if n not in loaded]
    assert not missing, f"VLAN-lab ports missing from {SCEN_DIR.name}: {missing}"


def test_example_has_no_secrets_hashes_hostkeys_or_real_macs():
    text = EXAMPLE.read_text()
    assert "/home/" not in text
    # The access point's SSIDs of the Wi-Fi scan scenarios as hex: the
    # lab's own names, not a hash and not a secret.  The injection name is
    # 30 bytes (60 hex characters) and the look-alike name 15 (30), so only
    # the first one is long enough to look like a hash.
    allowed_hex = {
        "6e6577746f6e2d746573742d3c2f756e747275737465643e53595354454d",
        "6e6577746f6e2d746573742d496162",
    }
    hashes = set(re.findall(r"\b[0-9a-fA-F]{40,}\b", text))
    assert hashes <= allowed_hex, hashes
    # AA:BB:CC:DD:EE:FF is the --bssid metavar of the Wi-Fi helper (its argparse
    # help and docstrings), not a MAC of any device: the scenarios always pin
    # --bssid to the {p_wifi_bssid} var, read from the router at run time.
    # 02:00:00:00:00:b2 is the locally administered address the helper gives
    # the isolate pair's second vif (sta2) with `ip link set`: a value this repo
    # makes up, not one any device carries (the same shape as the drill
    # scenario's synthetic lease MAC).
    macs = set(re.findall(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b", text))
    assert macs <= {"AA:BB:CC:DD:EE:FF", "02:00:00:00:00:b2"}, macs
    assert not re.search(r"ssh-(?:rsa|ed25519)|ecdsa-sha2|BEGIN [A-Z ]*KEY|PVEAPIToken", text)
    assert "<sha256 of baseline.tar.gz>" in text


PATH_VARS = ("pulsar_known_hosts", "pulsar_admin_key", "pulsar_runner_key",
             "pulsar_root_pw")


def test_example_device_is_marked_lab(example_lab):
    dev = example_lab.devices["pulsar"]
    assert dev.lab is True
    assert "lab = true" in EXAMPLE.read_text()


def test_example_pins_board_name(example_lab):
    dev = example_lab.devices["pulsar"]
    assert dev.board_name
    assert re.search(r'^board_name = "', EXAMPLE.read_text(), re.M)
    assert "/tmp/sysinfo/board_name" in EXAMPLE.read_text()


_SSH_KEY_ARG = re.compile(r"""(?<!\S)-i\s+(?!\{pulsar_|"?\$)\S+""")
# The path vars the example defines: the host key of Pulsar and the host key
# of lab-wifi (the VM the Wi-Fi helper runs on).  Both are paths, not
# secrets, and both reach the scenarios only as a var.
_OTHER_SECRET = re.compile(
    r"UserKnownHostsFile=(?!\{pulsar_|\{lab_wifi_|/dev/null\b)\S+|(?<!\{)(?<![\w-])\S*\.pw\b")


def _secret_literals(text):
    """Literal key, known_hosts or .pw paths; only the {pulsar_*} vars may
    name them (the runner's $LAB_SSH_KEY for the ISP VM and /dev/null are not
    Pulsar material). `-i` counts on ssh lines (busybox `udhcpc -i eth2` does not)."""
    found = []
    for line in text.splitlines():
        found += _OTHER_SECRET.findall(line)
        if re.search(r"\bssh\w*\b", line):
            found += _SSH_KEY_ARG.findall(line)
    return found


@pytest.mark.parametrize("text", [
    "ssh -i /home/user/key root@h", "ssh -i ~/.ssh/k root@h",
    "ssh -i key root@h", "ssh -o UserKnownHostsFile=/home/user/kh2 h",
    "ssh -o UserKnownHostsFile=~/kh h", "cat /tmp/x/root.pw", "cat ~/a.pw"])
def test_literal_detector_catches_reviewer_examples(text):
    assert _secret_literals(text), text


@pytest.mark.parametrize("text", [
    "ssh -i {pulsar_admin_key} -o UserKnownHostsFile={pulsar_known_hosts} h",
    "cat {pulsar_root_pw}", "ssh -i {pulsar_runner_key} h"])
def test_literal_detector_allows_path_vars(text):
    assert not _secret_literals(text), text


def test_scenarios_have_no_literal_key_known_hosts_or_pw_paths():
    for f in sorted(SCEN_DIR.glob("*.toml")):
        assert not _secret_literals(f.read_text()), f.name


def test_scenarios_and_example_name_no_literal_secret_paths():
    """Key, host-key and password file paths come from the path vars, so the
    example and the scenarios cannot drift apart on a file name."""
    for f in sorted(SCEN_DIR.glob("*.toml")):
        text = f.read_text()
        assert "~/.config" not in text and "~/.ssh" not in text, f.name
        assert "claude-root" not in text and "pulsar-lab-runner" not in text, f.name
    lab_text = EXAMPLE.read_text()
    for lineno, line in enumerate(lab_text.splitlines(), 1):
        if line.lstrip().startswith("#"):
            continue
        if "~/.config/newton" in line:
            # only the device table, [ssh] and the path vars may name files,
            # and a [vars.NAME] cmd may only `echo` the path or `cat` the one
            # file a secret var reads (the Wi-Fi PSK, whose value is masked
            # everywhere and never substituted outside a batch)
            assert re.match(r'\s*(\w+ = "~/|cmd = "(echo|cat) ~/)', line), (lineno, line)


def test_path_vars_resolve_to_the_device_table_paths(example_lab, home):
    for v in PATH_VARS:
        assert v in example_lab.var_defs
        assert example_lab.var_defs[v]["device"] == "local"
    def path(v):
        cmd = example_lab.var_defs[v]["cmd"]
        assert cmd.startswith("echo ~/") and " " not in cmd[len("echo "):], cmd
        return os.path.expanduser(cmd[len("echo "):])
    dev = example_lab.devices["pulsar"]
    assert path("pulsar_known_hosts") == dev.known_hosts
    assert path("pulsar_admin_key") == dev.admin_key
    assert path("pulsar_runner_key") == dev.router_key
    assert path("pulsar_root_pw") == os.path.expanduser(
        example_lab.ssh_password_file)


def test_every_path_var_the_scenarios_use_is_one_of_the_path_vars(scenarios):
    texts = []
    for s in scenarios:
        texts.append(s.batch)
        for p in s.post + s.effects:
            texts.append(p.cmd)
    used = {u for u in nl.used_placeholders(*texts)
            if u.startswith("pulsar_")}
    assert used and used <= set(PATH_VARS), used
