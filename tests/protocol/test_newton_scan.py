"""RT-11: the vantage forced command has one closed scan grammar."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCAN = ROOT / "scripts" / "newton-scan"


def make_fake_path(tmp_path):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    calls = tmp_path / "calls"

    timeout = fake_bin / "timeout"
    timeout.write_text(
        "#!/bin/sh\n"
        "set -eu\n"
        "{ printf 'timeout\\n'; printf '%s\\n' \"$@\"; } >>\"$NEWTON_SCAN_CALLS\"\n"
        "[ \"$1\" = 300 ]\n"
        "shift\n"
        "exec \"$@\"\n"
    )
    timeout.chmod(0o755)

    nmap = fake_bin / "nmap"
    nmap.write_text(
        "#!/bin/sh\n"
        "set -eu\n"
        "{ printf 'nmap\\n'; printf '%s\\n' \"$@\"; } >>\"$NEWTON_SCAN_CALLS\"\n"
    )
    nmap.chmod(0o755)

    env = os.environ.copy()
    env["PATH"] = str(fake_bin)
    env["NEWTON_SCAN_CALLS"] = str(calls)
    return env, calls


def run_scan(tmp_path, command_marker, *, unset=False):
    env, calls = make_fake_path(tmp_path)
    if unset:
        env.pop("SSH_ORIGINAL_COMMAND", None)
    else:
        env["SSH_ORIGINAL_COMMAND"] = command_marker
    result = subprocess.run(
        ["/bin/sh", str(SCAN)],
        text=True,
        capture_output=True,
        env=env,
        timeout=5,
    )
    lines = calls.read_text().splitlines() if calls.exists() else []
    return result, lines


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        (
            "scan quick inside 192.0.2.7",
            [
                "timeout", "300", "nmap", "-sT", "-T3", "--max-rate", "50",
                "--host-timeout", "60s", "--max-retries", "1", "--top-ports",
                "100", "-oG", "-", "192.0.2.7", "nmap", "-sT", "-T3",
                "--max-rate", "50", "--host-timeout", "60s", "--max-retries",
                "1", "--top-ports", "100", "-oG", "-", "192.0.2.7",
            ],
        ),
        (
            "scan quick outside 198.51.100.0/24",
            [
                "timeout", "300", "nmap", "-sT", "-Pn", "-T3", "--max-rate",
                "50", "--host-timeout", "60s", "--max-retries", "1",
                "--top-ports", "100", "-oG", "-", "198.51.100.0/24",
                "nmap", "-sT", "-Pn", "-T3", "--max-rate", "50",
                "--host-timeout", "60s", "--max-retries", "1", "--top-ports",
                "100", "-oG", "-", "198.51.100.0/24",
            ],
        ),
        (
            "scan full-tcp inside 203.0.113.9",
            [
                "timeout", "300", "nmap", "-sT", "-Pn", "-T3", "--min-rate",
                "300", "--max-rate", "300", "--host-timeout", "270s",
                "--max-retries", "0", "-p",
                "1-65535", "-oG", "-", "203.0.113.9", "nmap", "-sT",
                "-Pn", "-T3", "--min-rate", "300", "--max-rate", "300",
                "--host-timeout", "270s", "--max-retries", "0", "-p", "1-65535", "-oG", "-",
                "203.0.113.9",
            ],
        ),
        (
            "scan full-tcp outside 255.255.255.255",
            [
                "timeout", "300", "nmap", "-sT", "-Pn", "-T3", "--min-rate",
                "300", "--max-rate", "300", "--host-timeout", "270s",
                "--max-retries", "0", "-p",
                "1-65535", "-oG", "-", "255.255.255.255", "nmap", "-sT",
                "-Pn", "-T3", "--min-rate", "300", "--max-rate", "300",
                "--host-timeout", "270s", "--max-retries", "0", "-p", "1-65535", "-oG", "-",
                "255.255.255.255",
            ],
        ),
    ],
)
def test_accepted_grammar_execs_only_fixed_argv(tmp_path, command, expected):
    result, calls = run_scan(tmp_path, command)
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
    assert calls == expected


REFUSED = [
    pytest.param("", False, id="empty"),
    pytest.param("ignored", True, id="unset"),
    pytest.param("scan quick inside 192.0.2.1 extra", False, id="extra-token"),
    pytest.param("scan quick inside --script", False, id="script-flag"),
    pytest.param("scan quick inside -sC", False, id="default-script-flag"),
    pytest.param("scan quick inside -O", False, id="os-flag"),
    pytest.param("scan quick inside -sV", False, id="version-flag"),
    pytest.param("scan quick inside -sU", False, id="udp-flag"),
    pytest.param("scan quick inside -oX", False, id="xml-flag"),
    pytest.param("scan quick inside -192.0.2.1", False, id="flag-like-target"),
    pytest.param("scan quick inside 192.0.2.1;id", False, id="semicolon"),
    pytest.param("scan quick inside 192.0.2.1|id", False, id="pipe"),
    pytest.param("scan quick inside $(id)", False, id="dollar-command"),
    pytest.param("scan quick inside `id`", False, id="backticks"),
    pytest.param("scan quick inside 192.0.2.1\nid", False, id="newline"),
    pytest.param("scan quick inside example.test", False, id="hostname"),
    pytest.param("scan quick inside 2001:db8::1", False, id="ipv6"),
    pytest.param("scan quick inside 192.0.2.0/23", False, id="wide-network"),
    pytest.param("scan quick inside 0.0.0.0/0", False, id="default-route"),
    pytest.param("scan quick inside 192.168.001.1", False, id="leading-zero"),
    pytest.param("scan quick inside 256.1.1.1", False, id="large-octet"),
    pytest.param("scan QUICK inside 192.0.2.1", False, id="uppercase-profile"),
    pytest.param("scan quick INSIDE 192.0.2.1", False, id="uppercase-kind"),
    pytest.param("scan inside quick 192.0.2.1", False, id="profile-kind-swapped"),
    pytest.param("quick scan inside 192.0.2.1", False, id="verb-profile-swapped"),
    pytest.param(" scan quick inside 192.0.2.1", False, id="leading-space"),
    pytest.param("scan  quick inside 192.0.2.1", False, id="double-space"),
    pytest.param("scan quick inside 192.0.2.1 ", False, id="trailing-space"),
    pytest.param("scan quick inside 1.2.3", False, id="three-octets"),
    pytest.param("scan quick inside 1.2.3.4.5", False, id="five-octets"),
    pytest.param("scan quick inside 1.2.3.4/33", False, id="large-prefix"),
    # full-tcp is host-scoped on the vantage; refuse a /prefix target.
    pytest.param("scan full-tcp inside 192.0.2.7/32", False, id="full-tcp-inside-prefix"),
    pytest.param("scan full-tcp outside 198.51.100.9/24", False, id="full-tcp-outside-prefix"),
    pytest.param("scan full-tcp inside 192.0.2.0/24", False, id="full-tcp-inside-network"),
]


@pytest.mark.parametrize(("command", "unset"), REFUSED)
def test_refused_grammar_never_calls_nmap(tmp_path, command, unset):
    result, calls = run_scan(tmp_path, command, unset=unset)
    assert result.returncode == 2
    assert result.stdout == ""
    assert result.stderr == "newton-scan: refused\n"
    assert calls == []


def test_script_is_posix_sh_with_no_dangerous_nmap_features():
    text = SCAN.read_text()
    assert text.startswith("#!/bin/sh\n")
    assert "set -eu" in text
    assert "eval" not in text
    assert "sh -c" not in text
    for forbidden in ("--script", "-sC", "-O", "-sV", "-sU"):
        assert forbidden not in text


def test_busybox_and_shellcheck_accept_script():
    busybox = shutil.which("busybox")
    if busybox is None:
        pytest.skip("busybox is unavailable")
    syntax = subprocess.run(
        [busybox, "sh", "-n", str(SCAN)], text=True, capture_output=True, timeout=5
    )
    assert syntax.returncode == 0, syntax.stderr

    shellcheck = shutil.which("shellcheck")
    if shellcheck is not None:
        checked = subprocess.run(
            [shellcheck, "-S", "warning", str(SCAN)],
            text=True,
            capture_output=True,
            timeout=10,
        )
        assert checked.returncode == 0, checked.stdout + checked.stderr
