"""Offline execution tests for manifest checks that were made live."""

import os
import re
import subprocess
import tempfile
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "profiles" / "openwrt" / "manifest.toml"
SCENARIOS = ROOT / "lab" / "scenarios" / "openwrt"


def entry(control_id, tier):
    controls = tomllib.load(open(MANIFEST, "rb"))["control"]
    return next(item for item in controls
                if item["id"] == control_id and item["tier"] == tier)


def shell_run(check, env=None):
    stubs = r'''
netstat() {
  case "$*" in
    *-lun*) printf '%s\n' "${STUB_UDP:-}" ;;
    *-ltn*) printf '%s\n' "${STUB_TCP:-}" ;;
    *) printf '%s\n' "${STUB_NETSTAT:-}" ;;
  esac
}
ps() { printf '%s\n' "${STUB_PS:-}"; }
pidof() { printf '%s\n' "${STUB_PIDOF:-123}"; }
'''
    merged = os.environ.copy()
    merged.update(env or {})
    return subprocess.run(["sh", "-c", stubs + "\n" + check],
                          capture_output=True, text=True, env=merged)


def assert_good(item, result, label):
    context = f'{item["id"]} {item["tier"]}: {label}'
    assert result.returncode == 0, context + "\n" + result.stdout + result.stderr
    assert re.search(item["expect"], result.stdout, re.MULTILINE), (
        context + "\n" + result.stdout
    )


def assert_bad(item, result, label):
    context = f'{item["id"]} {item["tier"]}: {label}'
    assert (result.returncode != 0
            or not re.search(item["expect"], result.stdout, re.MULTILINE)), (
        context + "\n" + result.stdout + result.stderr
    )


def replace_proc_path(check, exact, data, context):
    assert exact in check, context
    handle = tempfile.NamedTemporaryFile(delete=False)
    try:
        handle.write(data)
        handle.close()
        return check.replace(exact, handle.name), Path(handle.name)
    except Exception:
        Path(handle.name).unlink(missing_ok=True)
        raise


DROPBEAR_CMDLINE = "/proc/$(cat /var/run/dropbear.main.pid)/cmdline"
UHTTPD_CMDLINE = "/proc/$(pidof uhttpd | cut -d' ' -f1)/cmdline"

CMDLINE_PATHS = {
    ("OW-MGMT-01", "lockdown"): DROPBEAR_CMDLINE,
    ("OW-MGMT-03", "standard"): UHTTPD_CMDLINE,
    ("OW-MGMT-05", "hardened"): DROPBEAR_CMDLINE,
}

GOOD_CASES = {
    ("OW-MGMT-01", "standard"): [
        ("management listener owned by dropbear", {
            "STUB_NETSTAT":
                "tcp 0 0 10.109.0.11:22 0.0.0.0:* LISTEN 123/dropbear",
        }, None),
    ],
    ("OW-MGMT-01", "lockdown"): [
        ("exact br-lan device", {}, b"dropbear\0-l\0br-lan\0"),
    ],
    ("OW-MGMT-03", "standard"): [
        ("quiet flag", {}, b"uhttpd\0-q\0"),
    ],
    ("OW-MGMT-05", "hardened"): [
        ("idle then auth limits", {},
         b"\0".join((b"dropbear", b"-I", b"600", b"-T", b"3", b""))),
        ("auth then idle limits", {},
         b"\0".join((b"dropbear", b"-T", b"3", b"-I", b"600", b""))),
    ],
    ("OW-FW-06", "standard"): [
        ("no targeted listener or process", {
            "STUB_UDP": "udp harmless",
            "STUB_TCP": "tcp harmless",
            "STUB_PS": "PID USER COMMAND",
        }, None),
    ],
}

BAD_CASES = {
    ("OW-MGMT-01", "standard"): [
        ("wildcard listener only", {
            "STUB_NETSTAT":
                "tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN 123/dropbear",
        }, None),
        ("management and IPv4 wildcard listeners", {
            "STUB_NETSTAT":
                "tcp 0 0 10.109.0.11:22 0.0.0.0:* LISTEN 123/dropbear\n"
                "tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN 123/dropbear",
        }, None),
        ("management and IPv6 wildcard listeners", {
            "STUB_NETSTAT":
                "tcp 0 0 10.109.0.11:22 0.0.0.0:* LISTEN 123/dropbear\n"
                "tcp 0 0 :::22 :::* LISTEN 123/dropbear",
        }, None),
        ("management listener owned by uhttpd", {
            "STUB_NETSTAT":
                "tcp 0 0 10.109.0.11:22 0.0.0.0:* LISTEN 123/uhttpd",
        }, None),
        ("no listener", {"STUB_NETSTAT": ""}, None),
    ],
    ("OW-MGMT-01", "lockdown"): [
        ("command line without -l", {},
         b"\0".join((b"dropbear", b"-p", b"22", b""))),
        ("wrong eth0 device", {}, b"dropbear\0-l\0eth0\0"),
        ("br-lan prefix only", {}, b"dropbear\0-l\0br-lan2\0"),
    ],
    ("OW-MGMT-03", "standard"): [
        ("foreground flag", {}, b"uhttpd\0-f\0"),
        ("double quiet flag", {}, b"uhttpd\0-qq\0"),
    ],
    ("OW-MGMT-05", "hardened"): [
        ("auth limit without idle limit", {},
         b"\0".join((b"dropbear", b"-T", b"3", b""))),
        ("idle limit without auth limit", {},
         b"\0".join((b"dropbear", b"-I", b"600", b""))),
        ("wrong auth limit", {},
         b"\0".join((b"dropbear", b"-I", b"600", b"-T", b"5", b""))),
        ("idle limit prefix", {},
         b"\0".join((b"dropbear", b"-I", b"6000", b"-T", b"3", b""))),
        ("auth limit prefix", {},
         b"\0".join((b"dropbear", b"-I", b"600", b"-T", b"30", b""))),
    ],
    ("OW-FW-06", "standard"): [
        ("udp 1900 listener", {
            "STUB_UDP": "udp 0 0 0.0.0.0:1900 0.0.0.0:*",
            "STUB_TCP": "tcp harmless",
            "STUB_PS": "PID USER COMMAND",
        }, None),
        ("udp 5351 listener", {
            "STUB_UDP": "udp 0 0 0.0.0.0:5351 0.0.0.0:*",
            "STUB_TCP": "tcp harmless",
            "STUB_PS": "PID USER COMMAND",
        }, None),
        ("tcp 5000 listener", {
            "STUB_UDP": "udp harmless",
            "STUB_TCP": "tcp 0 0 0.0.0.0:5000 0.0.0.0:* LISTEN",
            "STUB_PS": "PID USER COMMAND",
        }, None),
        ("miniupnpd process", {
            "STUB_UDP": "udp harmless",
            "STUB_TCP": "tcp harmless",
            "STUB_PS":
                "  123 root  1234 S    /usr/sbin/miniupnpd "
                "-f /var/etc/miniupnpd.conf",
        }, None),
    ],
}


def test_f3_offline_live_checks_pass_in_a_good_state():
    for (control_id, tier), cases in GOOD_CASES.items():
        item = entry(control_id, tier)
        for label, stubs, cmdline in cases:
            context = f"{control_id} {tier}: {label}"
            check = item["check"]
            path = None
            try:
                if cmdline is not None:
                    exact = CMDLINE_PATHS.get((control_id, tier))
                    assert exact is not None, context
                    check, path = replace_proc_path(
                        check, exact, cmdline, context)
                assert_good(item, shell_run(check, stubs), label)
            finally:
                if path is not None:
                    path.unlink(missing_ok=True)


def test_f3_offline_live_checks_fail_in_a_bad_state():
    for (control_id, tier), cases in BAD_CASES.items():
        item = entry(control_id, tier)
        for label, stubs, cmdline in cases:
            context = f"{control_id} {tier}: {label}"
            check = item["check"]
            path = None
            try:
                if cmdline is not None:
                    exact = CMDLINE_PATHS.get((control_id, tier))
                    assert exact is not None, context
                    check, path = replace_proc_path(
                        check, exact, cmdline, context)
                assert_bad(item, shell_run(check, stubs), label)
            finally:
                if path is not None:
                    path.unlink(missing_ok=True)


def test_n2_checks_check_py_cannot_compare_have_offline_cases():
    controls = tomllib.load(open(MANIFEST, "rb"))["control"]
    collected = set()
    scenarios = {}
    for item in controls:
        check_from = item["check_from"]
        if check_from == "derived":
            collected.add((item["id"], item["tier"]))
            continue
        match = re.fullmatch(r"(effect|post):(\d+)", check_from)
        if match is None:
            continue
        scenario_name = item["scenario"]
        scenario = scenarios.setdefault(
            scenario_name,
            tomllib.loads((SCENARIOS / scenario_name).read_text()),
        )
        kind, index_text = match.groups()
        step = scenario[kind][int(index_text)]
        if "expect_stdout" not in step:
            collected.add((item["id"], item["tier"]))

    required = {
        ("OW-MGMT-01", "standard"),
        ("OW-MGMT-01", "lockdown"),
        ("OW-MGMT-03", "standard"),
        ("OW-MGMT-05", "hardened"),
    }
    assert required <= collected
    for key in collected:
        label = f"{key[0]} {key[1]}"
        assert key in GOOD_CASES, f"{label}: missing from GOOD_CASES"
        assert key in BAD_CASES, f"{label}: missing from BAD_CASES"
