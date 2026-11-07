import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "newton-lab-isolation"

ALLOWED_MAC = "b8:27:eb:1a:2b:3c"
FILTER = (
    "(udp src port 67) or (udp src port 547) or (icmp6 and ip6[40] == 134) "
    "or (vlan and ((udp src port 67) or (udp src port 547) "
    "or (icmp6 and ip6[40] == 134)))"
)


def run(*args, env=None):
    return subprocess.run(
        [str(SCRIPT), *args], text=True, capture_output=True, env=env, timeout=10
    )


def dhcp_offer(src_mac, server="192.168.4.9", client="255.255.255.255"):
    return (
        f"19:06:41.123457 {src_mac} > ff:ff:ff:ff:ff:ff, ethertype IPv4 (0x0800), "
        f"length 286: {server}.67 > {client}.68: BOOTP/DHCP, Reply, length 244"
    )


def router_advert(src_mac, src="fe80::1"):
    return (
        f"19:06:42.123458 {src_mac} > 33:33:00:00:00:01, ethertype IPv6 (0x86dd), "
        f"length 70: {src} > ff02::1: ICMP6, router advertisement, length 16"
    )


def write_capture(tmp_path, lines):
    capture = tmp_path / "capture.txt"
    capture.write_text("".join(line + "\n" for line in lines))
    return capture


def install_fake(tmp_path, name, body):
    bindir = tmp_path / "bin"
    bindir.mkdir(parents=True, exist_ok=True)
    fake = bindir / name
    fake.write_text("#!/bin/sh\n" + body)
    fake.chmod(0o755)
    return bindir


def install_expiring_timeout(tmp_path):
    return install_fake(tmp_path, "timeout", "shift\n\"$@\"\nexit 124\n")


def fake_root_env(bindir):
    env = os.environ.copy()
    env["PATH"] = f"{bindir}:{env['PATH']}"
    return env


def test_from_file_only_allowed_sources_passes(tmp_path):
    capture = write_capture(
        tmp_path,
        [dhcp_offer(ALLOWED_MAC), dhcp_offer(ALLOWED_MAC), router_advert(ALLOWED_MAC)],
    )

    result = run(
        "--iface", "eth0", "--allow-mac", ALLOWED_MAC, "--from-file", str(capture)
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.splitlines() == [
        f"INFO {ALLOWED_MAC} dhcp-server x2 (allowed)",
        f"INFO {ALLOWED_MAC} router-advert x1 (allowed)",
        "PASS no foreign DHCP server or router advert on eth0 in 120 s "
        "(3 packets from allowed sources)",
    ]


def test_from_file_foreign_dhcp_offer_fails(tmp_path):
    foreign = "aa:bb:cc:00:11:22"
    capture = write_capture(
        tmp_path, [dhcp_offer(ALLOWED_MAC), dhcp_offer(foreign)]
    )

    result = run(
        "--iface", "eth0", "--allow-mac", ALLOWED_MAC, "--from-file", str(capture)
    )

    assert result.returncode == 1
    assert f"FAIL foreign[{foreign}]: dhcp-server x1 not in allow list" in (
        result.stdout
    )
    assert "PASS" not in result.stdout


def test_from_file_foreign_router_advert_fails(tmp_path):
    foreign = "11:22:33:44:55:66"
    capture = write_capture(tmp_path, [router_advert(foreign)])

    result = run(
        "--iface", "eth0", "--allow-mac", ALLOWED_MAC, "--from-file", str(capture)
    )

    assert result.returncode == 1
    assert f"FAIL foreign[{foreign}]: router-advert x1 not in allow list" in (
        result.stdout
    )
    assert "PASS" not in result.stdout


def test_from_file_no_packets_passes_with_zero_count(tmp_path):
    capture = write_capture(tmp_path, [])

    result = run(
        "--iface", "eth0", "--allow-mac", ALLOWED_MAC, "--from-file", str(capture)
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.splitlines() == [
        "PASS no foreign DHCP server or router advert on eth0 in 120 s "
        "(0 packets from allowed sources)",
    ]


def test_from_file_uppercase_allow_mac_is_accepted(tmp_path):
    capture = write_capture(tmp_path, [dhcp_offer(ALLOWED_MAC)])

    result = run(
        "--iface", "eth0", "--allow-mac", "B8:27:EB:1A:2B:3C", "--from-file", str(capture)
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.splitlines() == [
        f"INFO {ALLOWED_MAC} dhcp-server x1 (allowed)",
        "PASS no foreign DHCP server or router advert on eth0 in 120 s "
        "(1 packet from allowed sources)",
    ]


def test_from_file_seconds_leading_zeros_prints_without_them(tmp_path):
    capture = write_capture(tmp_path, [])

    result = run(
        "--iface", "eth0", "--allow-mac", ALLOWED_MAC,
        "--seconds", "012", "--from-file", str(capture),
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.splitlines() == [
        "PASS no foreign DHCP server or router advert on eth0 in 12 s "
        "(0 packets from allowed sources)",
    ]


def test_from_file_unreadable_capture_exits_2(tmp_path):
    result = run(
        "--iface",
        "eth0",
        "--allow-mac",
        ALLOWED_MAC,
        "--from-file",
        str(tmp_path / "missing.txt"),
    )

    assert result.returncode == 2
    assert "cannot read capture file" in result.stderr
    assert "PASS" not in result.stdout


@pytest.mark.parametrize(
    ("args", "fragment"),
    [
        (["--allow-mac", ALLOWED_MAC], "usage: newton-lab-isolation"),
        (["--iface", "eth0"], "usage: newton-lab-isolation"),
        (["--iface", "eth0; rm -rf /", "--allow-mac", ALLOWED_MAC], "invalid interface name"),
        (["--iface", "a" * 16, "--allow-mac", ALLOWED_MAC], "invalid interface name"),
        (["--iface", "eth0", "--allow-mac", "not-a-mac"], "invalid MAC"),
        (["--iface", "eth0", "--allow-mac", "b8:27:eb:1a:2b:3"], "invalid MAC"),
        (["--iface", "eth0", "--allow-mac", "00:11:22:33:44:55:66"], "invalid MAC"),
        (["--iface", "eth0", "--allow-mac", ALLOWED_MAC, "--seconds", "9"], "seconds"),
        (["--iface", "eth0", "--allow-mac", ALLOWED_MAC, "--seconds", "3601"], "seconds"),
        (["--iface", "eth0", "--allow-mac", ALLOWED_MAC, "--seconds", "abc"], "seconds"),
        (["--iface", "eth0", "--allow-mac", ALLOWED_MAC, "--seconds", "12345"], "seconds"),
    ],
)
def test_bad_arguments_exit_2(args, fragment):
    result = run(*args)

    assert result.returncode == 2
    assert fragment in result.stderr
    assert "PASS" not in result.stdout


@pytest.mark.skipif(os.geteuid() == 0, reason="test assumes an unprivileged user")
def test_non_root_without_from_file_refuses():
    result = run("--iface", "eth0", "--allow-mac", ALLOWED_MAC, "--seconds", "10")

    assert result.returncode == 2
    assert "packet capture needs root" in result.stderr
    assert "PASS" not in result.stdout


def test_capture_pins_tcpdump_invocation_and_passes(tmp_path):
    args_file = tmp_path / "tcpdump-args"
    body = f"printf '%s\\n' \"$@\" > {shlex.quote(str(args_file))}\n"
    for line in (dhcp_offer(ALLOWED_MAC), router_advert(ALLOWED_MAC)):
        body += f"printf '%s\\n' {shlex.quote(line)}\n"
    body += "exit 0\n"
    bindir = install_fake(tmp_path, "id", "printf '0\\n'\n")
    install_fake(tmp_path, "tcpdump", body)
    install_expiring_timeout(tmp_path)
    env = fake_root_env(bindir)

    result = run(
        "--iface", "eth0", "--allow-mac", ALLOWED_MAC, "--seconds", "10", env=env
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert args_file.read_text().splitlines() == [
        "-n",
        "-e",
        "-l",
        "-i",
        "eth0",
        "-c",
        "10000",
        FILTER,
    ]
    assert result.stdout.splitlines() == [
        f"INFO {ALLOWED_MAC} dhcp-server x1 (allowed)",
        f"INFO {ALLOWED_MAC} router-advert x1 (allowed)",
        "PASS no foreign DHCP server or router advert on eth0 in 10 s "
        "(2 packets from allowed sources)",
    ]


def test_capture_allowed_sources_pass_with_packet_count(tmp_path):
    body = ""
    for line in (dhcp_offer(ALLOWED_MAC), dhcp_offer(ALLOWED_MAC), router_advert(ALLOWED_MAC)):
        body += f"printf '%s\\n' {shlex.quote(line)}\n"
    body += "exit 0\n"
    bindir = install_fake(tmp_path, "id", "printf '0\\n'\n")
    install_fake(tmp_path, "tcpdump", body)
    install_expiring_timeout(tmp_path)
    env = fake_root_env(bindir)

    result = run(
        "--iface", "eth0", "--allow-mac", ALLOWED_MAC, "--seconds", "10", env=env
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.splitlines() == [
        f"INFO {ALLOWED_MAC} dhcp-server x2 (allowed)",
        f"INFO {ALLOWED_MAC} router-advert x1 (allowed)",
        "PASS no foreign DHCP server or router advert on eth0 in 10 s "
        "(3 packets from allowed sources)",
    ]


def test_capture_foreign_dhcp_offer_exits_1_and_names_the_mac(tmp_path):
    foreign = "aa:bb:cc:00:11:22"
    bindir = install_fake(tmp_path, "id", "printf '0\\n'\n")
    install_fake(
        tmp_path,
        "tcpdump",
        f"printf '%s\\n' {shlex.quote(dhcp_offer(foreign))}\nexit 0\n",
    )
    install_expiring_timeout(tmp_path)
    env = fake_root_env(bindir)

    result = run(
        "--iface", "eth0", "--allow-mac", ALLOWED_MAC, "--seconds", "10", env=env
    )

    assert result.returncode == 1, result.stdout + result.stderr
    assert result.stdout.splitlines() == [
        f"FAIL foreign[{foreign}]: dhcp-server x1 not in allow list",
        "FAIL foreign DHCP server or router advert on eth0 in 10 s "
        "(1 packet from foreign sources)",
    ]


def test_capture_tcpdump_failure_exits_2_and_never_passes(tmp_path):
    bindir = install_fake(tmp_path, "id", "printf '0\\n'\n")
    install_fake(
        tmp_path,
        "tcpdump",
        "printf 'tcpdump: eth0: No such device exists\\n' >&2\nexit 1\n",
    )
    env = fake_root_env(bindir)

    result = run(
        "--iface", "eth0", "--allow-mac", ALLOWED_MAC, "--seconds", "10", env=env
    )

    assert result.returncode == 2
    assert "tcpdump: eth0: No such device exists" in result.stderr
    assert "ERROR: tcpdump failed with status 1" in result.stderr
    assert "PASS" not in result.stdout


def test_capture_timeout_kill_still_passes(tmp_path):
    real_timeout = shutil.which("timeout")
    assert real_timeout is not None
    timeout_args = tmp_path / "timeout-args"
    bindir = install_fake(
        tmp_path,
        "timeout",
        f"printf '%s\\n' \"$@\" > {shlex.quote(str(timeout_args))}\n"
        "dur=$1\nshift\n"
        f"exec {shlex.quote(real_timeout)} 1 \"$@\"\n",
    )
    install_fake(tmp_path, "id", "printf '0\\n'\n")
    install_fake(
        tmp_path,
        "tcpdump",
        f"printf '%s\\n' {shlex.quote(dhcp_offer(ALLOWED_MAC))}\n"
        "exec sleep 30\n",
    )
    env = fake_root_env(bindir)

    result = run(
        "--iface", "eth0", "--allow-mac", ALLOWED_MAC, "--seconds", "10", env=env
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert timeout_args.read_text().splitlines()[0] == "10"
    assert result.stdout.splitlines() == [
        f"INFO {ALLOWED_MAC} dhcp-server x1 (allowed)",
        "PASS no foreign DHCP server or router advert on eth0 in 10 s "
        "(1 packet from allowed sources)",
    ]


def test_from_file_any_iface_line_is_unreadable(tmp_path):
    capture = write_capture(
        tmp_path,
        [
            "17:13:20.000000  In aa:bb:cc:00:11:22 ethertype IPv4 (0x0800), "
            "length 342: 192.168.4.9.67 > 255.255.255.255.68: "
            "BOOTP/DHCP, Reply, length 300",
        ],
    )

    result = run(
        "--iface", "eth0", "--allow-mac", ALLOWED_MAC, "--from-file", str(capture)
    )

    assert result.returncode == 1, result.stdout + result.stderr
    assert "FAIL unreadable: 1 line could not be attributed" in result.stdout
    assert "FAIL foreign[unknown]: unreadable x1 not in allow list" in result.stdout
    assert "first: 17:13:20.000000  In aa:bb:cc:00:11:22" in result.stdout
    assert result.stdout.splitlines()[-1] == (
        "FAIL foreign DHCP server or router advert on eth0 in 120 s "
        "(1 packet from foreign sources)"
    )
    assert "PASS" not in result.stdout


def test_from_file_raw_ip_line_is_unreadable(tmp_path):
    capture = write_capture(
        tmp_path,
        [
            "17:13:20.000000 ip: 192.168.4.9.67 > 255.255.255.255.68: "
            "BOOTP/DHCP, Reply, length 300",
        ],
    )

    result = run(
        "--iface", "eth0", "--allow-mac", ALLOWED_MAC, "--from-file", str(capture)
    )

    assert result.returncode == 1, result.stdout + result.stderr
    assert "FAIL unreadable: 1 line could not be attributed" in result.stdout
    assert "FAIL foreign[unknown]: unreadable x1 not in allow list" in result.stdout
    assert result.stdout.splitlines()[-1] == (
        "FAIL foreign DHCP server or router advert on eth0 in 120 s "
        "(1 packet from foreign sources)"
    )
    assert "PASS" not in result.stdout


def test_from_file_unclassifiable_ethernet_line_is_unreadable(tmp_path):
    capture = write_capture(
        tmp_path,
        [
            "19:06:41.123457 aa:bb:cc:00:11:22 > ff:ff:ff:ff:ff:ff, "
            "ethertype IPv4 (0x0800), length 60: 192.168.4.9.1234 > "
            "192.168.4.50.80: Flags [S], seq 1, win 1024, length 0",
        ],
    )

    result = run(
        "--iface", "eth0", "--allow-mac", ALLOWED_MAC, "--from-file", str(capture)
    )

    assert result.returncode == 1, result.stdout + result.stderr
    assert "FAIL unreadable: 1 line could not be attributed" in result.stdout
    assert "PASS" not in result.stdout


def test_from_file_two_unreadable_lines_are_counted(tmp_path):
    capture = write_capture(
        tmp_path,
        [
            "17:13:20.000000 ip: 192.168.4.9.67 > 255.255.255.255.68: "
            "BOOTP/DHCP, Reply, length 300",
            "17:13:20.000001 ip: 192.168.4.9.67 > 255.255.255.255.68: "
            "BOOTP/DHCP, Reply, length 300",
        ],
    )

    result = run(
        "--iface", "eth0", "--allow-mac", ALLOWED_MAC, "--from-file", str(capture)
    )

    assert result.returncode == 1, result.stdout + result.stderr
    assert "FAIL unreadable: 2 lines could not be attributed" in result.stdout
    assert "FAIL foreign[unknown]: unreadable x2 not in allow list" in result.stdout
    assert result.stdout.splitlines()[-1] == (
        "FAIL foreign DHCP server or router advert on eth0 in 120 s "
        "(2 packets from foreign sources)"
    )
    assert "PASS" not in result.stdout


def test_from_file_banner_and_summary_lines_are_ignored(tmp_path):
    capture = write_capture(
        tmp_path,
        [
            "reading from file x.pcap, link-type EN10MB (Ethernet), "
            "snapshot length 262144",
            "tcpdump: verbose output suppressed, use -v[v]... for full "
            "protocol decode",
            "listening on eth0, link-type EN10MB (Ethernet), "
            "snapshot length 262144 bytes",
            "",
            dhcp_offer(ALLOWED_MAC),
            "1 packet captured",
            "1 packet received by filter",
            "0 packets dropped by kernel",
        ],
    )

    result = run(
        "--iface", "eth0", "--allow-mac", ALLOWED_MAC, "--from-file", str(capture)
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.splitlines() == [
        f"INFO {ALLOWED_MAC} dhcp-server x1 (allowed)",
        "PASS no foreign DHCP server or router advert on eth0 in 120 s "
        "(1 packet from allowed sources)",
    ]


def test_capture_early_tcpdump_exit_exits_2_and_never_passes(tmp_path):
    body = f"printf '%s\\n' {shlex.quote(dhcp_offer(ALLOWED_MAC))}\nexit 0\n"
    bindir = install_fake(tmp_path, "id", "printf '0\\n'\n")
    install_fake(tmp_path, "tcpdump", body)
    env = fake_root_env(bindir)

    result = run(
        "--iface", "eth0", "--allow-mac", ALLOWED_MAC, "--seconds", "10", env=env
    )

    assert result.returncode == 2, result.stdout + result.stderr
    match = re.search(r"stopped after (\d+) s of the 10 s window", result.stderr)
    assert match is not None, result.stderr
    assert int(match.group(1)) < 10
    assert "of the 10 s window" in result.stderr
    assert "no PASS is reported" in result.stderr
    assert result.stdout.splitlines() == [
        f"INFO {ALLOWED_MAC} dhcp-server x1 (allowed)",
    ]
    assert "PASS" not in result.stdout


def test_capture_early_exit_with_foreign_packet_still_fails(tmp_path):
    foreign = "aa:bb:cc:00:11:22"
    bindir = install_fake(tmp_path, "id", "printf '0\\n'\n")
    install_fake(
        tmp_path,
        "tcpdump",
        f"printf '%s\\n' {shlex.quote(dhcp_offer(foreign))}\nexit 0\n",
    )
    env = fake_root_env(bindir)

    result = run(
        "--iface", "eth0", "--allow-mac", ALLOWED_MAC, "--seconds", "10", env=env
    )

    assert result.returncode == 1, result.stdout + result.stderr
    assert f"FAIL foreign[{foreign}]: dhcp-server x1 not in allow list" in (
        result.stdout
    )
    summary = re.search(
        r"^FAIL foreign DHCP server or router advert on eth0 in (\d+) s "
        r"\(1 packet from foreign sources\)$",
        result.stdout.splitlines()[-1],
    )
    assert summary is not None, result.stdout
    assert int(summary.group(1)) < 10


def test_from_file_foreign_dhcpv6_offer_fails(tmp_path):
    foreign = "aa:bb:cc:00:11:22"
    capture = write_capture(
        tmp_path,
        [
            "19:06:41.123457 aa:bb:cc:00:11:22 > 33:33:00:01:00:02, "
            "ethertype IPv6 (0x86dd), length 66: fe80::5.547 > ff02::1:2.546: "
            "dhcp6 advertise",
        ],
    )

    result = run(
        "--iface", "eth0", "--allow-mac", ALLOWED_MAC, "--from-file", str(capture)
    )

    assert result.returncode == 1, result.stdout + result.stderr
    assert f"FAIL foreign[{foreign}]: dhcpv6-server x1 not in allow list" in (
        result.stdout
    )
    assert "PASS" not in result.stdout


def test_from_file_allowed_dhcpv6_offer_passes(tmp_path):
    allowed = "aa:bb:cc:00:11:22"
    capture = write_capture(
        tmp_path,
        [
            "19:06:41.123457 aa:bb:cc:00:11:22 > 33:33:00:01:00:02, "
            "ethertype IPv6 (0x86dd), length 66: fe80::5.547 > ff02::1:2.546: "
            "dhcp6 advertise",
        ],
    )

    result = run(
        "--iface", "eth0", "--allow-mac", allowed, "--from-file", str(capture)
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.splitlines() == [
        f"INFO {allowed} dhcpv6-server x1 (allowed)",
        "PASS no foreign DHCP server or router advert on eth0 in 120 s "
        "(1 packet from allowed sources)",
    ]


def test_capture_missing_tcpdump_exits_2(tmp_path):
    bindir = install_fake(tmp_path, "id", "printf '0\\n'\n")
    for dir_ in os.environ["PATH"].split(os.pathsep):
        try:
            entries = os.listdir(dir_)
        except OSError:
            continue
        for name in entries:
            candidate = Path(dir_) / name
            if (bindir / name).exists() or name == "tcpdump":
                continue
            if candidate.is_file() and os.access(candidate, os.X_OK):
                os.symlink(candidate, bindir / name)
    env = fake_root_env(bindir)
    env["PATH"] = str(bindir)

    result = run(
        "--iface", "eth0", "--allow-mac", ALLOWED_MAC, "--seconds", "10", env=env
    )

    assert result.returncode == 2
    assert "tcpdump not found in PATH" in result.stderr
    assert "PASS" not in result.stdout


def test_capture_temp_dir_honours_tmpdir_and_is_cleaned(tmp_path):
    tmpdir = tmp_path / "tmp"
    tmpdir.mkdir()
    fd1_file = tmp_path / "fd1.txt"
    body = f"exec 9>&1\nreadlink /proc/self/fd/9 > {shlex.quote(str(fd1_file))}\n"
    body += f"printf '%s\\n' {shlex.quote(dhcp_offer(ALLOWED_MAC))}\nexit 0\n"
    bindir = install_fake(tmp_path, "id", "printf '0\\n'\n")
    install_fake(tmp_path, "tcpdump", body)
    install_expiring_timeout(tmp_path)
    env = fake_root_env(bindir)
    env["TMPDIR"] = str(tmpdir)

    result = run(
        "--iface", "eth0", "--allow-mac", ALLOWED_MAC, "--seconds", "10", env=env
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert fd1_file.read_text().strip().startswith(str(tmpdir) + "/")
    assert os.listdir(tmpdir) == []


def test_capture_temp_dir_is_cleaned_after_tcpdump_failure(tmp_path):
    tmpdir = tmp_path / "tmp"
    tmpdir.mkdir()
    bindir = install_fake(tmp_path, "id", "printf '0\\n'\n")
    install_fake(tmp_path, "tcpdump", "exit 1\n")
    env = fake_root_env(bindir)
    env["TMPDIR"] = str(tmpdir)

    result = run(
        "--iface", "eth0", "--allow-mac", ALLOWED_MAC, "--seconds", "10", env=env
    )

    assert result.returncode == 2
    assert os.listdir(tmpdir) == []


def test_from_file_last_line_without_trailing_newline_is_parsed(tmp_path):
    foreign = "aa:bb:cc:00:11:22"
    capture = tmp_path / "capture.txt"
    capture.write_text(dhcp_offer(foreign))

    result = run(
        "--iface", "eth0", "--allow-mac", ALLOWED_MAC, "--from-file", str(capture)
    )

    assert result.returncode == 1
    assert f"FAIL foreign[{foreign}]: dhcp-server x1 not in allow list" in (
        result.stdout
    )
    assert "PASS" not in result.stdout


@pytest.mark.parametrize("flag", ["--help", "-h"])
def test_help_exits_0(flag):
    result = run(flag)

    assert result.returncode == 0
    assert "usage: newton-lab-isolation" in result.stdout
    assert "--allow-mac" in result.stdout
    assert "--seconds" in result.stdout
    assert "sudo scripts/newton-lab-isolation --iface eth0 --allow-mac" in (
        result.stdout
    )
    assert result.stderr == ""


def test_unknown_option_exits_2():
    result = run("--iface", "eth0", "--allow-mac", ALLOWED_MAC, "--bogus")

    assert result.returncode == 2
    assert "ERROR: unknown option: --bogus" in result.stderr
    assert "usage: newton-lab-isolation" in result.stderr
    assert "PASS" not in result.stdout


def test_from_file_zero_packets_prints_note_on_stderr(tmp_path):
    capture = write_capture(tmp_path, [])

    result = run(
        "--iface", "eth0", "--allow-mac", ALLOWED_MAC, "--from-file", str(capture)
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.splitlines() == [
        "PASS no foreign DHCP server or router advert on eth0 in 120 s "
        "(0 packets from allowed sources)",
    ]
    assert "NOTE: no DHCP or router advert packet was seen" in result.stderr


def test_from_file_one_allowed_packet_prints_no_note(tmp_path):
    capture = write_capture(tmp_path, [dhcp_offer(ALLOWED_MAC)])

    result = run(
        "--iface", "eth0", "--allow-mac", ALLOWED_MAC, "--from-file", str(capture)
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "NOTE" not in result.stderr


def test_from_file_plural_packet_counts(tmp_path):
    foreign = "aa:bb:cc:00:11:22"
    allowed_capture = tmp_path / "allowed.txt"
    allowed_capture.write_text(
        "".join(line + "\n" for line in (dhcp_offer(ALLOWED_MAC), router_advert(ALLOWED_MAC)))
    )
    foreign_capture = tmp_path / "foreign.txt"
    foreign_capture.write_text(
        "".join(line + "\n" for line in (dhcp_offer(foreign), dhcp_offer(foreign)))
    )

    allowed_result = run(
        "--iface", "eth0", "--allow-mac", ALLOWED_MAC,
        "--from-file", str(allowed_capture),
    )
    foreign_result = run(
        "--iface", "eth0", "--allow-mac", ALLOWED_MAC,
        "--from-file", str(foreign_capture),
    )

    assert allowed_result.returncode == 0, allowed_result.stdout
    assert allowed_result.stdout.splitlines()[-1] == (
        "PASS no foreign DHCP server or router advert on eth0 in 120 s "
        "(2 packets from allowed sources)"
    )
    assert foreign_result.returncode == 1
    assert foreign_result.stdout.splitlines()[-1] == (
        "FAIL foreign DHCP server or router advert on eth0 in 120 s "
        "(2 packets from foreign sources)"
    )


def test_from_file_vlan_tagged_offer_fails(tmp_path):
    foreign = "aa:bb:cc:00:11:22"
    capture = write_capture(
        tmp_path,
        [
            "19:06:41.123457 aa:bb:cc:00:11:22 > ff:ff:ff:ff:ff:ff, "
            "ethertype 802.1Q (0x8100), length 290: vlan 20, p 0, "
            "ethertype IPv4 (0x0800), 192.168.4.9.67 > 255.255.255.255.68: "
            "BOOTP/DHCP, Reply, length 244",
        ],
    )

    result = run(
        "--iface", "eth0", "--allow-mac", ALLOWED_MAC, "--from-file", str(capture)
    )

    assert result.returncode == 1, result.stdout + result.stderr
    assert f"FAIL foreign[{foreign}]: dhcp-server x1 not in allow list" in (
        result.stdout
    )
    assert "PASS" not in result.stdout
